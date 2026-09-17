"""Offline attack-onset forecasting console."""
from pathlib import Path
import hashlib
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import torch
from demo.helpers import (PACKET_FEATURES, attack_intervals, benign_references,
    campaign_label, first_sustained, history_at, host_catalog, ingest_upload)
from src.data.windowing import apply_scaler
from src.inference.engine import load_forecaster, lead_time_seconds, explain_window, FEATURE_LABELS
from src.explain.shap_wrapper import RiskExplainer
from src.mitre.stage_mapping import STAGE_NAMES, STAGE_TACTICS, STAGE_DESCRIPTIONS, stage_order

st.set_page_config(page_title='Network Attack Forecasting', layout='wide')
st.markdown('''<style>
html,body,[data-testid="stApp"],button,input {font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
.stApp p,.stApp label,.stApp h1,.stApp h2,.stApp h3 {font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
.stApp {background:#20252b;color:#d6dce0;}
[data-testid="stMainBlockContainer"] {padding:1.5rem 2rem;max-width:1800px;}
[data-testid="stMetricValue"],table,code {font-family:ui-monospace,Consolas,monospace;}
[data-baseweb="select"] input {font-family:ui-monospace,Consolas,monospace!important;}
[data-testid="stIconMaterial"], [data-testid="stElementToolbar"] {display:none!important;}
button,input,[data-baseweb="select"]>div,[data-testid="stExpander"], [data-testid="stFileUploader"] {border-radius:2px!important;box-shadow:none!important;}
[data-testid="stToolbar"], [data-testid="stStatusWidget"], [data-testid="stSpinner"] {display:none!important;}
[data-testid="stSkeleton"] {visibility:hidden!important;animation:none!important;}
.stApp * {animation:none!important;transition:none!important;border-radius:2px!important;}
h1 {font-size:1.45rem!important;} h2,h3 {font-size:1.05rem!important;}
</style>''', unsafe_allow_html=True)
COLORS = {1:'#789aa9',2:'#b29a60',4:'#ac7068'}

@st.cache_data(show_spinner=False)
def gallery(path, modified):
    return pd.read_parquet(path)

@st.cache_resource(show_spinner=False)
def forecaster(path, modified):
    torch.set_num_threads(2)
    return load_forecaster(path, device='cpu'), threading.RLock()

@st.cache_data(show_spinner=False)
def catalog(source, campaign, length, _frame):
    return host_catalog(_frame, length)

@st.cache_resource(show_spinner=False)
def explanation_resource(path, modified, gallery_path, gallery_modified):
    separate = load_forecaster(path, device='cpu')
    raw = benign_references(gallery(gallery_path, gallery_modified), separate.feature_names, separate.history_length)
    background = apply_scaler(raw, separate.scaler)
    explainer = RiskExplainer(separate.model, background, feature_names=separate.feature_names, horizon=4, device='cpu')
    return separate, explainer, pd.Series(np.median(raw.reshape(-1,raw.shape[-1]),axis=0),index=separate.feature_names), threading.RLock()

@st.cache_data(show_spinner=False, max_entries=40)
def replay_timeline(checkpoint, modified, source, host_id, mc, _host):
    model, lock = forecaster(checkpoint, modified)
    with lock:
        return model.forecast_host_timeline(_host, mc_samples=mc)

@st.cache_data(show_spinner=False, max_entries=100)
def replay_explanation(checkpoint, modified, source, host_id, timestamp, gallery_path, gallery_modified, _host):
    return explain_focus(checkpoint,modified,gallery_path,gallery_modified,_host,timestamp)

def explain_focus(checkpoint, modified, gallery_path, gallery_modified, host, timestamp):
    model, explainer, baseline, lock = explanation_resource(checkpoint,modified,gallery_path,gallery_modified)
    history, raw = history_at(host,timestamp,model.feature_names,model.history_length)
    with lock:
        attribution = explainer.explain_batch(apply_scaler(raw,model.scaler))[0]
    sentence, drivers = explain_window(history.iloc[-1],baseline,model.feature_names,top_k=4)
    return attribution, sentence.replace('\u2014','-'), drivers, baseline

def chart_style(fig, height=280):
    fig.update_layout(height=height, margin=dict(l=10,r=10,t=25,b=25),
        paper_bgcolor='#20252b',plot_bgcolor='#20252b',font=dict(family='Consolas',color='#d6dce0'),
        legend=dict(orientation='h',y=1.15), hovermode='x unified')
    fig.update_xaxes(gridcolor='#363e46',zeroline=False)
    fig.update_yaxes(gridcolor='#363e46',zeroline=False)
    return fig

def render(host,timeline,model,primary,known,focus,attribution,sentence,drivers,baseline,mc):
    key=f'risk_k{primary}'
    threshold=model.threshold_for_horizon(primary)
    lead=lead_time_seconds(timeline,horizon_key=key,threshold=threshold) if known else None
    if lead is None:
        text='Unavailable - labels unknown' if not known else 'Unavailable'
    elif lead > 0:
        text=f'{lead:.0f} s early'
    else:
        text=f'{abs(lead):.0f} s late' if lead < 0 else '0 s - no advance warning'
    st.metric(f'Warning lead time | +{primary*30} s', text)
    if known and lead is None:
        st.caption('No qualified sustained alert or labelled attack in forecast rows.')
    st.caption('Two consecutive alerts; confirmation at the close of the second 30-second window. Lead time uses the existing inference API.')
    st.subheader('Risk timeline')
    fig=go.Figure()
    if known:
        for start,end in attack_intervals(host):
            fig.add_vrect(x0=start,x1=end,fillcolor='#ac7068',opacity=.16,line_width=0,layer='below')
    for k in model.horizons:
        if mc:
            fig.add_trace(go.Scatter(x=timeline.window_start,y=timeline[f'risk_lo_k{k}'],line=dict(width=0),showlegend=False,hoverinfo='skip'))
            fig.add_trace(go.Scatter(x=timeline.window_start,y=timeline[f'risk_hi_k{k}'],fill='tonexty',fillcolor='rgba(120,154,169,0.09)',line=dict(width=0),showlegend=False,hoverinfo='skip'))
        fig.add_trace(go.Scatter(x=timeline.window_start,y=timeline[f'risk_k{k}'],name=f'+{30*k} s',line=dict(color=COLORS[k],width=3 if k==primary else 1)))
    fig.add_hline(y=threshold,line_dash='dash',line_color=COLORS[primary],annotation_text=f'+{primary*30}s threshold {threshold:.4f}')
    alert=first_sustained(timeline,key,threshold)
    if alert:
        fig.add_trace(go.Scatter(x=[alert[0]],y=[alert[1]],mode='markers',marker=dict(symbol='square',size=9,color='#b29a60'),name='First sustained alert confirmed'))
    fig.update_yaxes(range=[0,1],title='Forecast risk')
    st.plotly_chart(chart_style(fig,320),width='stretch',config={'displayModeBar':False},key='risk')
    st.caption('Time axis: UTC window start. Shading: recorded attack labels.' if known else 'Time axis: UTC window start. Uploaded traffic is unlabelled; no ground truth is inferred.')
    st.subheader('ATT&CK stage progression | +120 s')
    order=list(stage_order())
    stage=go.Figure(go.Scatter(x=timeline.window_start,y=timeline.stage_k4,mode='lines+markers',line=dict(color='#789aa9',width=1),marker=dict(size=4),
        text=[f'{STAGE_NAMES[int(s)]} | {STAGE_TACTICS[int(s)]}<br>{STAGE_DESCRIPTIONS[int(s)]}' for s in timeline.stage_k4],hovertemplate='%{x}<br>%{text}<extra></extra>'))
    stage.update_yaxes(tickvals=order,ticktext=[STAGE_NAMES[s] for s in order],range=[-.4,6.4])
    st.plotly_chart(chart_style(stage,260),width='stretch',config={'displayModeBar':False},key='stages')
    st.caption('Predicted stages may repeat or move backwards. Stage labels are predictions, not confirmed compromise.')
    st.subheader('Flagged flows - 30-second host windows')
    flagged=timeline.loc[timeline.risk_k4>=model.threshold_for_horizon(4)].merge(host,on='window_start',validate='one_to_one').sort_values('window_start',ascending=False)
    rows=[]
    for _,row in flagged.iterrows():
        _, elevated=explain_window(row,baseline,model.feature_names,top_k=4)
        rows.append({'UTC window':row.window_start,'+120 s risk':row.risk_k4,'Predicted stage':STAGE_NAMES[int(row.stage_k4)],
                     'Elevated observed values':'; '.join(f'{f}={v:.4g}' for f,v,_ in elevated) or 'No elevated features'})
    st.dataframe(pd.DataFrame(rows,columns=['UTC window','+120 s risk','Predicted stage','Elevated observed values']),hide_index=True,width='stretch')
    if not rows:
        st.caption('No +120-second forecasts exceed the checkpoint threshold for this host.')
    st.subheader('Focused forecast explanation')
    st.caption(f'{focus} | Deterministic +120 s risk: {attribution.prediction:.5f}. SHAP and attention explain the deterministic forecast' + ('; the timeline shows a 20-pass MC mean.' if mc else '.'))
    top=attribution.top_features(5)
    names=[f'{"Packet" if n in PACKET_FEATURES else "Flow / behavior"} | {FEATURE_LABELS.get(n,n)} ({n})' for n,_ in top]
    shapfig=go.Figure(go.Bar(x=[v for _,v in top],y=names,orientation='h',marker_color=['#ac7068' if v>0 else '#719980' for _,v in top]))
    shapfig.update_xaxes(title='Signed SHAP contribution to risk')
    shapfig.update_yaxes(autorange='reversed')
    st.plotly_chart(chart_style(shapfig,260),width='stretch',config={'displayModeBar':False},key='shap')
    history,_=history_at(host,focus,model.feature_names,model.history_length)
    weights=np.asarray(timeline.loc[timeline.window_start==focus,'attn_k4'].iloc[0])
    attention=go.Figure(go.Bar(x=history.window_start,y=weights,marker_color='#789aa9'))
    attention.update_yaxes(title='Attention weight')
    st.write('Which past 30s windows drove this forecast')
    st.plotly_chart(chart_style(attention,190),width='stretch',config={'displayModeBar':False},key='attention')
    st.caption('Attention weights describe model weighting, not causal evidence.')
    st.write('Observed elevation versus the benign gallery reference')
    st.write(sentence)
    st.caption('The sentence compares actual feature values with a labelled benign gallery reference, not this host\'s verified normal or SHAP attribution.')
    current=history.iloc[-1]
    with st.expander('Focused feature values - flow / behavior and packet-derived'):
        for label,features in [('Flow / behavior',[f for f in model.feature_names if f not in PACKET_FEATURES]),('Packet-derived',list(PACKET_FEATURES))]:
            st.write(label)
            st.dataframe(pd.DataFrame({'Feature':features,'Observed':[current[f] for f in features],'Benign reference':[baseline[f] for f in features]}),hide_index=True,width='stretch')

def main():
    st.title('Network Attack Forecasting')
    st.write('Forecast attack onset at +30/+60/+120 seconds to support warning before compromise.')
    with st.expander('About the benchmark'):
        st.write('The recorded wm_final benchmark in RESULTS.md beats persistence and logistic regression at each horizon on PR-AUC and F1. Absolute results remain modest, consistent with the limited precursor signal in onset data. This is not a benchmark of uploaded captures.')
        st.dataframe(pd.DataFrame({'Horizon':['+30 s','+60 s','+120 s'],'World model PR-AUC':[.077,.071,.079],'Persistence PR-AUC':[.000,.001,.001],'Logistic regression PR-AUC':[.030,.032,.033],'World model F1':[.087,.136,.128]}),hide_index=True)
    checkpoint=str(ROOT/'models/wm_final/best.ckpt')
    modified=Path(checkpoint).stat().st_mtime_ns
    candidates=list((ROOT/'data/processed').glob('windows_cicids2017_all_+2018_+ctu13_*.parquet'))
    if not candidates:
        st.error('No gallery parquet found in data/processed. The labelled gallery is also required for SHAP reference histories.')
        return
    path=max(candidates,key=lambda p:p.stat().st_mtime_ns)
    gp,gm=str(path),path.stat().st_mtime_ns
    model,_=forecaster(checkpoint,modified)
    controls,panel=st.columns([1,3.6],gap='large')
    with controls:
        st.subheader('Controls')
        source=st.radio('Data source',['Dataset replay','Upload capture'])
        known=source=='Dataset replay'
        if known:
            data=gallery(gp,gm)
            campaign=st.selectbox('Campaign',sorted(data.campaign_id.unique()),format_func=campaign_label)
            frame=data.loc[data.campaign_id==campaign]
            source_key=f'{gp}:{gm}:{campaign}'
            hosts=catalog(source_key,campaign,model.history_length,frame)
            eligible=hosts.loc[hosts.forecasts>0]
            attacked=eligible.loc[eligible.attacked]
            if attacked.empty:
                st.write('No attacked host has 10 consecutive 30-second windows.' if hosts.attacked.any() else 'Benign-only replay: no attack labels in this campaign.')
                if not st.checkbox('Select benign-host replay explicitly',key=f'benign_{campaign}'):
                    return
                eligible=eligible.loc[~eligible.attacked]
            else:
                eligible=attacked
        else:
            st.caption('Local-only processing. Maximum 200 MB; conversion timeout five minutes. CSV, PCAP and PCAPNG. Files are removed after processing; windows remain in this session. Labels are unknown.')
            st.caption('PCAP uses CICFlowMeter. On systems without tcpdump, an offline Scapy reader feeds the same CICFlowMeter feature engine.')
            upload=st.file_uploader('Capture file',type=['csv','pcap','pcapng'])
            if upload is None:
                return
            payload=upload.getvalue()
            digest=hashlib.sha256(payload).hexdigest()
            source_key=f'upload:{digest}'
            if st.session_state.get('upload_digest')!=digest:
                status=st.empty();status.text('computing...')
                try:
                    frame,audit=ingest_upload(payload,Path(upload.name).suffix.lower())
                finally:
                    status.empty()
                st.session_state.update(upload_digest=digest,upload_frame=frame,upload_audit=audit,upload_results={},upload_explanations={})
            frame=st.session_state.upload_frame
            with st.expander('Feature availability audit'):
                st.json(st.session_state.upload_audit)
            eligible=host_catalog(frame,model.history_length)
            eligible=eligible.loc[eligible.forecasts>0]
        if eligible.empty:
            st.write('Insufficient history: no host has 10 consecutive 30-second windows. Histories are not padded.')
            return
        host_id=st.selectbox('Host',eligible.host.tolist())
        primary=st.selectbox('Primary horizon',[1,2,4],index=2,format_func=lambda k:f'+{k*30} s')
        mc=20 if st.checkbox('MC-dropout uncertainty (20 passes)') else 0
        host=frame.loc[frame.entity_id.astype(str)==host_id].sort_values('window_start').reset_index(drop=True)
        status=st.empty();status.text('computing...')
        try:
            if known:
                timeline=replay_timeline(checkpoint,modified,source_key,host_id,mc,host)
            else:
                cachekey=(checkpoint,modified,source_key,host_id,mc)
                cache=st.session_state.upload_results
                if cachekey not in cache:
                    _,lock=forecaster(checkpoint,modified)
                    with lock:
                        cache[cachekey]=model.forecast_host_timeline(host,mc_samples=mc)
                timeline=cache[cachekey]
        finally:
            status.empty()
        flagged=timeline.index[timeline.risk_k4>=model.threshold_for_horizon(4)]
        default=int(flagged[0]) if len(flagged) else int(timeline.risk_k4.idxmax())
        focus=st.selectbox('Focused forecast time (UTC)',timeline.window_start.tolist(),index=default,key=f'focus:{source_key}:{host_id}:{mc}')
        st.caption(f'{len(host):,} observed windows | {len(timeline):,} forecasts | CPU')
    with panel:
        status=st.empty();status.text('computing...')
        try:
            if known:
                explanation=replay_explanation(checkpoint,modified,source_key,host_id,focus,gp,gm,host)
            else:
                ek=(checkpoint,modified,source_key,host_id,focus)
                if ek not in st.session_state.upload_explanations:
                    st.session_state.upload_explanations[ek]=explain_focus(checkpoint,modified,gp,gm,host,focus)
                explanation=st.session_state.upload_explanations[ek]
        finally:
            status.empty()
        render(host,timeline,model,primary,known,focus,*explanation,mc)

try:
    main()
except (ValueError, OSError, RuntimeError, KeyError) as exc:
    st.error(f'Unable to compute this view: {exc}')
