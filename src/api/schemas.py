"""Pydantic request/response models for the NetraVerse API."""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class HostSummary(BaseModel):
    host: str
    peak: float
    first_alert_step: Optional[int]
    stage: int
    stage_name: str
    flows: int
    truth_attack_steps: Optional[int] = None


class UploadResponse(BaseModel):
    id: str
    source: str
    filename: str
    labelled: bool
    n_flows: Optional[int]
    n_hosts: int
    n_steps: int
    t0: float
    window_s: int
    horizon_s: int
    threshold: float
    focus_host: Optional[str]
    decision_step: Optional[int]
    hosts: list[HostSummary]
    model: dict[str, Any]


class Timeline(BaseModel):
    host: str
    threshold: float
    window_s: int
    horizon_s: int
    t: list[float]
    risk: list[float] = Field(description="P(attack involving this host within the 300 s horizon)")
    risk_now: list[float]
    future: list[list[float]] = Field(description="rollout P(attack) at +60..+300 s from each step")
    lo: list[list[float]]
    hi: list[list[float]]
    stage: list[int]
    stage_now: list[int]
    stage_names: list[str]
    present: list[bool]
    traffic: dict[str, list[int]]
    truth_stage: Optional[list[int]]
    first_alert_step: Optional[int]
    predicted_compromise_s_after_alert: Optional[int] = None
    actual_first_attack_step: Optional[int] = None
    lead_time_s: Optional[int] = None
    future_stage: list[list[int]] = Field(default_factory=list,
                                          description="forecast MITRE stage for each imagined step t+1..t+K")
    forecast_hit_step: Optional[int] = None
    forecast_lead_s: Optional[int] = Field(None, description="how long before the first labelled attack window "
                                                             "the rollout already forecast it above threshold")


class Driver(BaseModel):
    feature: str
    label: str
    attribution: float
    value: float
    typical: float
    sentence: str


class DecisionRequest(BaseModel):
    host: str
    step: int
    choice: Literal["accept", "modify", "reject"]
    action: Optional[Any] = None         # action id (or full action dict) for "modify"


class Topology(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    window: int
    step: Optional[int] = None
    branch: Optional[str] = None
