"""Offline attack-onset forecasting console."""
from pathlib import Path
import hashlib
import json
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
    campaign_label, first_sustained, forecast_log, history_at, host_catalog, ingest_upload)
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
.flowbox {border:1px solid #3a434c;background:#252b32;padding:8px 10px;min-height:64px;font-size:.82rem;}
.flowbox b {color:#9db4c0;font-family:ui-monospace,Consolas,monospace;}
.flowstep {color:#8a949c;font-size:.72rem;letter-spacing:.03em;}
</style>''', unsafe_allow_html=True)
COLORS = {1:'#789aa9',2:'#b29a60',4:'#ac7068'}

@st.cache_data(show_spinner=False)
def gallery(path, modified):
    return pd.read_parquet(path)

@st.cache_data(show_spinner=False)
def benchmark(path, modified):
    return json.loads(Path(path).read_text(encoding='utf-8'))

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
    return attribution, sentence.replace('—','-'), drivers, baseline

def chart_style(fig, height=280):
    fig.update_layout(height=height, margin=dict(l=10,r=10,t=25,b=25),
        paper_bgcolor='#20252b',plot_bgcolor='#20252b',font=dict(family='Consolas',color='#d6dce0'),
        legend=dict(orientation='h',y=1.15), hovermode='x unified')
    fig.update_xaxes(gridcolor='#363e46',zeroline=False)
    fig.update_yaxes(gridcolor='#363e46',zeroline=False)
    return fig

def story_strip(bench):
    st.title('Network Attack Forecasting')
    st.write('Forecasts an attack 30-120 seconds before it completes, and explains why - a weather '
             'forecast for the network, not a fire alarm that rings once the fire is already burning.')
    steps = [('1. Network traffic','flow records / packets on a host'),
             ('2. State S(t)','one 30-second per-host snapshot (43 features)'),
             ('3. World model','LSTM rolls the state forward K steps: S(t+1..t+K)'),
             ('4. Onset risk + stage','probability of attack in +30/+60/+120s, mapped to ATT&CK'),
             ('5. Explanation','SHAP + attention: which signals and which past windows')]
    cols = st.columns(len(steps))
    for col,(head,body) in zip(cols,steps):
        col.markdown(f'<div class="flowbox"><span class="flowstep">{head}</span><br><b>{body}</b></div>',unsafe_allow_html=True)
    st.caption('This is a world model - it predicts the future network state and scores that, '
               'instead of classifying the current packet like a traditional detector.')
    horizons = bench['horizons']
    table = {'Model': [r['model'] for r in bench['rows']]}
    for i,h in enumerate(horizons):
        table[f'PR-AUC {h}'] = [r['pr_auc'][i] for r in bench['rows']]
    for i,h in enumerate(horizons):
        table[f'F1 {h}'] = [r['f1'][i] for r in bench['rows']]
    st.markdown('**Benchmark (test split) - higher PR-AUC / F1 is better**')
    st.dataframe(pd.DataFrame(table),hide_index=True,width='stretch')
    st.caption(bench['takeaway'])

def cleaning_report(audit):
    c = audit.get('cleaning',{})
    st.markdown('**Ingest and clean (this uploaded file)**')
    steps = [('Rows read',c.get('rows_read')),('Empty rows dropped',c.get('empty_dropped')),
             ('Duplicate flows dropped',c.get('duplicates_dropped')),
             (f"Non-finite values imputed ({c.get('nonfinite_pct',0)}% of cells)",c.get('nonfinite_imputed')),
             ('Bad-timestamp rows dropped',c.get('bad_timestamp_dropped')),
             ('Missing source-IP rows dropped',c.get('missing_src_ip_dropped')),
             ('Clean flows kept',c.get('flows_kept')),('30-second windows built',c.get('windows_built')),
             ('Hosts with >=10 consecutive windows',c.get('hosts_with_history'))]
    st.dataframe(pd.DataFrame([(s,str(c)) for s,c in steps],columns=['Step','Count']),hide_index=True,width='stretch')
    az=set(audit.get('all_zero_columns',[]))
    pop=[p for p in PACKET_FEATURES if p not in az]
    st.caption(f"Column map detected: {audit['column_map']}. Packet-derived model features populated: "
               f"{len(pop)} of 9. All {audit['model_columns']} model features are finite. "
               "Labels are unknown for uploads, so risk and stage are predictions.")
    with st.expander('Details / raw audit'):
        st.json(audit)

def tab_forecast(host,timeline,model,primary,known,focus,mc):
    key=f'risk_k{primary}'
    threshold=model.threshold_for_horizon(primary)
    selected=timeline.loc[timeline.window_start==focus].iloc[0]
    issued=focus+pd.Timedelta(seconds=30)
    st.caption('What this shows: the forecast risk of an attack starting in the next 30/60/120 seconds, '
               'for each 30-second window. It should rise before the shaded real attack.')
    c1,c2,c3=st.columns(3)
    c1.metric(f'Focused onset risk | next {primary*30} s', f'{selected[key]:.1%}')
    peak=timeline.loc[timeline[key].idxmax()]
    c2.metric(f'Peak risk (this host)', f'{peak[key]:.1%}')
    c3.metric('Windows above threshold', f'{int((timeline[key]>=threshold).sum())} / {len(timeline)}')
    status='above' if selected[key]>=threshold else 'below'
    st.write(f'Focused window is **{status} the alert threshold** ({threshold:.4f}). '
             f'Forecast issued at {issued}, covering through {issued+pd.Timedelta(seconds=primary*30)}.')
    alert=first_sustained(timeline,key,threshold)
    lead=None
    if known:
        lead=lead_time_seconds(timeline,horizon_key=key,threshold=threshold)
        if lead is not None and lead>0:
            st.write(f'**Warning lead time: {lead:.0f} s** before the recorded attack (first sustained alert at {alert[0]}).')
        elif alert:
            st.write(f'First sustained alert at {alert[0]} (at or after attack start; no advance warning here).')
    fig=go.Figure()
    if known:
        first=True
        for start,end in attack_intervals(host):
            fig.add_vrect(x0=start,x1=end,fillcolor='#ac7068',opacity=.16,line_width=0,layer='below',
                          annotation_text='recorded attack' if first else None,annotation_position='top left')
            first=False
    for k in model.horizons:
        if mc:
            fig.add_trace(go.Scatter(x=timeline.window_start,y=timeline[f'risk_lo_k{k}'],line=dict(width=0),showlegend=False,hoverinfo='skip'))
            fig.add_trace(go.Scatter(x=timeline.window_start,y=timeline[f'risk_hi_k{k}'],fill='tonexty',fillcolor='rgba(120,154,169,0.09)',line=dict(width=0),showlegend=False,hoverinfo='skip'))
        fig.add_trace(go.Scatter(x=timeline.window_start,y=timeline[f'risk_k{k}'],name=f'+{30*k} s',line=dict(color=COLORS[k],width=3 if k==primary else 1)))
    fig.add_hline(y=threshold,line_dash='dash',line_color=COLORS[primary],annotation_text=f'+{primary*30}s threshold {threshold:.4f}')
    if alert:
        fig.add_trace(go.Scatter(x=[alert[0]],y=[alert[1]],mode='markers',marker=dict(symbol='square',size=9,color='#b29a60'),name='First sustained alert'))
    fig.update_yaxes(range=[0,1],title='Forecast risk')
    st.plotly_chart(chart_style(fig,320),width='stretch',config={'displayModeBar':False},key='risk')
    st.subheader('Forecast trajectory for the focused window')
    traj=go.Figure(go.Scatter(x=[f'+{k*30} s' for k in model.horizons],y=[selected[f'risk_k{k}'] for k in model.horizons],
        mode='lines+markers',line=dict(color=COLORS[primary],width=3),marker=dict(size=9)))
    traj.add_hline(y=threshold,line_dash='dash',line_color='#8a949c')
    traj.update_yaxes(range=[0,1],title='Predicted risk')
    st.plotly_chart(chart_style(traj,220),width='stretch',config={'displayModeBar':False},key='traj')
    st.caption('The world model rolls the current network state forward K steps and scores each predicted '
               'future window - this rising path is the forecast, before the attack completes.')
    with st.expander('Details / caveats'):
        st.write('Model risk score, not a calibrated probability or a confirmation of an attack. '
                 'Each point uses the preceding ten completed 30-second windows. Two consecutive '
                 'above-threshold forecasts are required for a sustained alert. '
                 + ('' if known else 'Uploads have no verified attack start, so lead time is not measured; use Dataset replay for labelled evaluation.'))
    return lead

def tab_trends(host,known):
    st.caption('What this shows: the raw traffic behaviour over time. A spike in distinct destination '
               'ports is a port scan; a spike in volume is a flood or brute force.')
    x=host.window_start
    shade=attack_intervals(host) if known else []
    v=go.Figure()
    for start,end in shade:
        v.add_vrect(x0=start,x1=end,fillcolor='#ac7068',opacity=.16,line_width=0,layer='below')
    v.add_trace(go.Scatter(x=x,y=host.n_flows,name='flows / 30 s',line=dict(color='#789aa9',width=2)))
    v.add_trace(go.Scatter(x=x,y=host.pkts_per_sec,name='packets / s',line=dict(color='#b29a60',width=1)))
    v.update_yaxes(title='volume')
    st.subheader('Traffic volume')
    st.plotly_chart(chart_style(v,240),width='stretch',config={'displayModeBar':False},key='vol')
    p=go.Figure()
    for start,end in shade:
        p.add_vrect(x0=start,x1=end,fillcolor='#ac7068',opacity=.16,line_width=0,layer='below')
    p.add_trace(go.Scatter(x=x,y=host.n_distinct_dst_port,name='distinct destination ports',line=dict(color='#ac7068',width=2)))
    p.add_trace(go.Scatter(x=x,y=host.dst_port_entropy,name='destination-port entropy',line=dict(color='#789aa9',width=1)))
    p.update_yaxes(title='fan-out')
    st.subheader('Destination-port activity (recon / scan signal)')
    st.plotly_chart(chart_style(p,240),width='stretch',config={'displayModeBar':False},key='ports')

def tab_stage(timeline):
    st.caption('What this shows: the attack stage the model predicts for each window, along the standard '
               'MITRE ATT&CK kill chain. Watch it advance from reconnaissance toward impact.')
    order=list(stage_order())
    stage=go.Figure(go.Scatter(x=timeline.window_start,y=timeline.stage_k4,mode='lines+markers',line=dict(color='#789aa9',width=1),marker=dict(size=4),
        text=[f'{STAGE_NAMES[int(s)]} | {STAGE_TACTICS[int(s)]}<br>{STAGE_DESCRIPTIONS[int(s)]}' for s in timeline.stage_k4],hovertemplate='%{x}<br>%{text}<extra></extra>'))
    stage.update_yaxes(tickvals=order,ticktext=[STAGE_NAMES[s] for s in order],range=[-.4,6.4])
    st.plotly_chart(chart_style(stage,300),width='stretch',config={'displayModeBar':False},key='stages')
    st.dataframe(pd.DataFrame([{'Stage':STAGE_NAMES[s],'ATT&CK tactic':STAGE_TACTICS[s] or '-','Meaning':STAGE_DESCRIPTIONS[s]} for s in order],
        ),hide_index=True,width='stretch')
    with st.expander('Details / caveats'):
        st.write('Predicted stages may repeat or move backwards; they are predictions at the +120 s horizon, '
                 'not confirmed compromise. DoS/DDoS map to IMPACT (TA0040).')

def tab_why(host,timeline,model,focus,attribution,sentence,baseline,mc):
    st.caption('What this shows: why the model raised the alarm - the top signals (SHAP), which past '
               'windows it focused on (attention), and a plain-English summary.')
    st.write(f'Focused window {focus}. Deterministic +120 s risk: {attribution.prediction:.5f}.'
             + (' Timeline shows a 20-pass MC-dropout mean.' if mc else ''))
    top=attribution.top_features(5)
    names=[f'{"Packet" if n in PACKET_FEATURES else "Flow / behavior"} | {FEATURE_LABELS.get(n,n)} ({n})' for n,_ in top]
    shapfig=go.Figure(go.Bar(x=[v for _,v in top],y=names,orientation='h',marker_color=['#ac7068' if v>0 else '#719980' for _,v in top]))
    shapfig.update_xaxes(title='Signed SHAP contribution to risk'); shapfig.update_yaxes(autorange='reversed')
    st.subheader('Top contributing features (SHAP)')
    st.plotly_chart(chart_style(shapfig,260),width='stretch',config={'displayModeBar':False},key='shap')
    history,_=history_at(host,focus,model.feature_names,model.history_length)
    weights=np.asarray(timeline.loc[timeline.window_start==focus,'attn_k4'].iloc[0])
    attention=go.Figure(go.Bar(x=history.window_start,y=weights,marker_color='#789aa9'))
    attention.update_yaxes(title='Attention weight')
    st.subheader('Which past 30-second windows drove this forecast (attention)')
    st.plotly_chart(chart_style(attention,190),width='stretch',config={'displayModeBar':False},key='attention')
    st.subheader('Plain-language summary')
    st.info(sentence)
    current=history.iloc[-1]
    with st.expander('Focused feature values - flow / behavior and packet-derived'):
        for label,features in [('Flow / behavior',[f for f in model.feature_names if f not in PACKET_FEATURES]),('Packet-derived',list(PACKET_FEATURES))]:
            st.write(label)
            st.dataframe(pd.DataFrame({'Feature':features,'Observed':[current[f] for f in features],'Benign reference':[baseline[f] for f in features]}),hide_index=True,width='stretch')
    with st.expander('Details / caveats'):
        st.write('SHAP explains the deterministic +120 s forecast against a benign gallery background. '
                 'Attention weights describe model weighting, not proven causation. The summary compares '
                 'observed values with a labelled benign reference, not this host\'s own verified normal.')

def tab_flagged(host,timeline,model,baseline):
    st.caption('What this shows: every 30-second window where the +120 s risk crossed the alert threshold, '
               'newest first, with the observed values that stood out.')
    flagged=timeline.loc[timeline.risk_k4>=model.threshold_for_horizon(4)].merge(host,on='window_start',validate='one_to_one').sort_values('window_start',ascending=False)
    rows=[]
    for _,row in flagged.iterrows():
        _, elevated=explain_window(row,baseline,model.feature_names,top_k=4)
        rows.append({'UTC window':row.window_start,'+120 s risk':row.risk_k4,'Predicted stage':STAGE_NAMES[int(row.stage_k4)],
                     'Elevated observed values':'; '.join(f'{f}={v:.4g}' for f,v,_ in elevated) or 'No elevated features'})
    if rows:
        st.dataframe(pd.DataFrame(rows),hide_index=True,width='stretch')
    else:
        st.write('No +120-second forecasts exceed the checkpoint threshold for this host.')

def tab_log(host,timeline,model,primary,baseline):
    st.caption('Session history and the model card. Every host you inspect is logged here.')
    log_rows=list(st.session_state.get('run_log',{}).values())
    if log_rows:
        st.subheader('Runs this session')
        st.dataframe(pd.DataFrame(log_rows),hide_index=True,width='stretch')
    st.subheader('Model card')
    cfg=model.model.config
    card={'Parameters':f'{model.model.num_parameters():,}','Input features':len(model.feature_names),
          'ATT&CK stages':cfg.n_stages,'Horizons':', '.join(f'+{k*30}s' for k in model.horizons),
          'Attention':bool(cfg.use_attention),'History':f'{model.history_length} x 30 s windows',
          'Training data':'CIC-IDS2017 (all days) + CIC-IDS2018 (IP day) + CTU-13 (7 scenarios)',
          'Training':'two-stage: benign-dynamics pretrain, then scheduled-sampling fine-tune (onset target)'}
    st.dataframe(pd.DataFrame([(k,str(v)) for k,v in card.items()],columns=['Field','Value']),hide_index=True,width='stretch')
    st.subheader('Full forecast log for the selected host')
    full=forecast_log(host,timeline,model.feature_names,baseline,
                      {k:model.threshold_for_horizon(k) for k in model.horizons},primary)
    st.download_button('Download complete forecast log (CSV)',full.to_csv(index=False).encode('utf-8'),
                       file_name='forecast_log.csv',mime='text/csv',on_click='ignore')

def render(host,timeline,model,primary,known,focus,attribution,sentence,drivers,baseline,mc):
    tabs=st.tabs(['Forecast','Network trends','ATT&CK stage','Why (explainability)','Flagged flows','Log and model card'])
    with tabs[0]:
        lead=tab_forecast(host,timeline,model,primary,known,focus,mc)
    with tabs[1]:
        tab_trends(host,known)
    with tabs[2]:
        tab_stage(timeline)
    with tabs[3]:
        tab_why(host,timeline,model,focus,attribution,sentence,baseline,mc)
    with tabs[4]:
        tab_flagged(host,timeline,model,baseline)
    with tabs[5]:
        tab_log(host,timeline,model,primary,baseline)
    return lead

def main():
    checkpoint=str(ROOT/'models/wm_final/best.ckpt')
    modified=Path(checkpoint).stat().st_mtime_ns
    bench_path=ROOT/'models/wm_final/benchmark.json'
    story_strip(benchmark(str(bench_path),bench_path.stat().st_mtime_ns))
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
            st.caption(f'Pre-cleaned labelled gallery: {len(data):,} windows across {data.campaign_id.nunique()} campaigns.')
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
            st.caption('Local-only processing. Max 200 MB; five-minute conversion timeout. CSV, PCAP, PCAPNG. '
                       'Files are removed after processing; labels are unknown.')
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
            cleaning_report(st.session_state.upload_audit)
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
        lead=render(host,timeline,model,primary,known,focus,*explanation,mc)
    # session run log (one row per inspected host)
    peak=timeline.loc[timeline.risk_k4.idxmax()]
    st.session_state.setdefault('run_log',{})[f'{source_key}:{host_id}']={
        'time':pd.Timestamp.now(tz='UTC').strftime('%H:%M:%S'),'source':'replay' if known else 'upload',
        'host':host_id,'peak +120s risk':f'{float(timeline.risk_k4.max()):.1%}',
        'lead (s)':('n/a' if not known or lead is None else f'{lead:.0f}'),
        'top stage':STAGE_NAMES[int(peak.stage_k4)]}

try:
    main()
except (ValueError, OSError, RuntimeError, KeyError) as exc:
    st.error(f'Unable to compute this view: {exc}')
