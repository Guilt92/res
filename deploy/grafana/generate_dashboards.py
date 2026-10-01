#!/usr/bin/env python3
"""Generate the six production Grafana dashboards for res.

Every panel queries real Prometheus series exported by the gateway
(`res_*`); nothing here invents data. Panels whose series do not exist
yet render Grafana's honest "No data" state (`noValue: "No data"`).

Usage:  python3 deploy/grafana/generate_dashboards.py
Output: deploy/grafana/dashboards/<uid>.json  (provisioned by Grafana)
"""

import json
import os

DS = {"type": "prometheus", "uid": "prometheus"}
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboards")

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

TS_CUSTOM = {
    "drawStyle": "line",
    "lineInterpolation": "linear",
    "lineWidth": 1,
    "fillOpacity": 8,
    "gradientMode": "none",
    "showPoints": "never",
    "pointSize": 5,
    "spanNulls": False,
    "insertNulls": False,
    "axisPlacement": "auto",
    "axisLabel": "",
    "axisColorMode": "text",
    "axisBorderShow": False,
    "axisCenteredZero": False,
    "scaleDistribution": {"type": "linear"},
    "hideFrom": {"legend": False, "tooltip": False, "viz": False},
    "thresholdsStyle": {"mode": "off"},
    "barAlignment": 0,
    "stacking": {"mode": "none", "group": "A"},
}


def target(expr, legend="", ref="A", table=False, instant=False, heatmap=False):
    t = {"datasource": DS, "refId": ref, "editorMode": "code", "expr": expr}
    if legend:
        t["legendFormat"] = legend
    if heatmap:
        t["format"] = "heatmap"
        t["range"] = True
    elif table:
        t["format"] = "table"
        t["instant"] = True
        t["range"] = False
    elif instant:
        t["instant"] = True
        t["range"] = False
    else:
        t["range"] = True
    return t


def defaults(unit=None, thresholds=None, mappings=None, decimals=None, minv=None, maxv=None):
    d = {"noValue": "No data", "mappings": mappings or []}
    if unit:
        d["unit"] = unit
    if decimals is not None:
        d["decimals"] = decimals
    if minv is not None:
        d["min"] = minv
    if maxv is not None:
        d["max"] = maxv
    if thresholds:
        d["thresholds"] = {"mode": "absolute", "steps": thresholds}
        d["color"] = {"mode": "thresholds"}
    return d


GREEN = [{"color": "green", "value": None}]


class Dashboard:
    def __init__(self, uid, title, description, tags):
        self.uid = uid
        self.title = title
        self.description = description
        self.tags = tags
        self.panels = []
        self._next_id = 1

    def _finish(self, p, x, y, w, h, targets):
        p["id"] = self._next_id
        self._next_id += 1
        p["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
        p["datasource"] = DS
        p["targets"] = targets
        self.panels.append(p)
        return p

    def timeseries(self, title, targets, x, y, w, h, unit=None, stacked=False,
                   fill=None, thresholds=None, decimals=None, description=None,
                   minv=None, maxv=None):
        custom = dict(TS_CUSTOM)
        if stacked:
            custom["stacking"] = {"mode": "normal", "group": "A"}
        custom["fillOpacity"] = fill if fill is not None else (25 if stacked else 8)
        p = {
            "type": "timeseries",
            "title": title,
            "fieldConfig": {
                "defaults": defaults(unit, thresholds, decimals=decimals,
                                     minv=minv, maxv=maxv),
                "overrides": [],
            },
            "options": {
                "legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "showLegend": True},
                "tooltip": {"mode": "multi", "sort": "desc"},
                "tooltipOptions": {"mode": "multi", "sort": "desc"},
            },
        }
        p["fieldConfig"]["defaults"]["custom"] = custom
        if description:
            p["description"] = description
        return self._finish(p, x, y, w, h, targets)

    def stat(self, title, expr, x, y, w, h, unit=None, thresholds=None, mappings=None,
             ref="A", instant=False, description=None, color_mode="value",
             graph_mode="none", decimals=None):
        p = {
            "type": "stat",
            "title": title,
            "fieldConfig": {
                "defaults": defaults(unit, thresholds, mappings, decimals=decimals),
                "overrides": [],
            },
            "options": {
                "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "orientation": "auto",
                "textMode": "auto",
                "wideLayout": True,
                "colorMode": color_mode,
                "graphMode": graph_mode,
                "justifyMode": "auto",
            },
        }
        if description:
            p["description"] = description
        return self._finish(p, x, y, w, h, [target(expr, ref=ref, instant=instant)])

    def table(self, title, targets, x, y, w, h, renames=None, unit=None, thresholds=None,
              description=None, sort_field=None, sort_desc=True):
        renames = renames or {}
        transformations = []
        if renames:
            transformations.append({
                "id": "organize",
                "options": {
                    "excludeByName": {"__name__": True, "Time": True, "timestamp": True},
                    "indexByName": {},
                    "renameByName": renames,
                },
            })
        if sort_field:
            transformations.append({
                "id": "sortBy",
                "options": {
                    "fields": {},
                    "sort": [{"field": sort_field, "desc": sort_desc}],
                },
            })
        p = {
            "type": "table",
            "title": title,
            "fieldConfig": {
                "defaults": defaults(unit, thresholds),
                "overrides": [],
            },
            "options": {
                "showHeader": True,
                "cellHeight": "sm",
                "footer": {"show": False, "reducer": ["sum"], "countRows": False, "fields": ""},
            },
        }
        if transformations:
            p["transformations"] = transformations
        if description:
            p["description"] = description
        return self._finish(p, x, y, w, h, targets)

    def bargauge(self, title, targets, x, y, w, h, unit=None, thresholds=None,
                 description=None, maxv=None, decimals=None):
        p = {
            "type": "bargauge",
            "title": title,
            "fieldConfig": {
                "defaults": defaults(unit, thresholds, maxv=maxv, decimals=decimals),
                "overrides": [],
            },
            "options": {
                "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "orientation": "horizontal",
                "displayMode": "basic",
                "showUnfilled": True,
                "minVizWidth": 0,
                "minVizHeight": 16,
                "maxVizHeight": 500,
                "valueMode": "color",
            },
        }
        if description:
            p["description"] = description
        return self._finish(p, x, y, w, h, targets)

    def heatmap(self, title, expr, x, y, w, h, description=None):
        p = {
            "type": "heatmap",
            "title": title,
            "fieldConfig": {
                "defaults": {"noValue": "No data", "custom": {"fillOpacity": 70,
                             "hideFrom": {"legend": False, "tooltip": False, "viz": False},
                             "spanNulls": False}},
                "overrides": [],
            },
            "options": {
                "calculateBucketDegree": False,
                "color": {"mode": "spectrum", "fill": "dark-orange", "scale": "exponential",
                          "exponent": 0.5, "reverse": False, "steps": 64},
                "yAxis": {"unit": "s", "placement": "auto", "reverse": False, "decimals": None},
                "rowsFrame": {"layout": "auto"},
                "tooltip": {"mode": "single", "yAxis": {"visible": True, "split": False}},
                "exemplars": {"color": "rgba(255,0,255,0.7)"},
            },
        }
        if description:
            p["description"] = description
        return self._finish(p, x, y, w, h, [target(expr, legend="{{le}}", ref="A", heatmap=True)])

    def state_timeline(self, title, expr, x, y, w, h, description=None):
        p = {
            "type": "state-timeline",
            "title": title,
            "fieldConfig": {
                "defaults": {
                    "noValue": "No data",
                    "mappings": [{
                        "type": "value",
                        "options": {
                            "0": {"text": "DOWN", "color": "red"},
                            "1": {"text": "DEGRADED", "color": "yellow"},
                            "2": {"text": "UP", "color": "green"},
                        },
                    }],
                    "thresholds": {"mode": "absolute", "steps": [
                        {"color": "red", "value": None},
                        {"color": "yellow", "value": 1},
                        {"color": "green", "value": 2},
                    ]},
                    "color": {"mode": "thresholds"},
                    "custom": {"hideFrom": {"legend": False, "tooltip": False, "viz": False}},
                },
                "overrides": [],
            },
            "options": {
                "mergeValues": True,
                "showValue": "never",
                "alignValue": "center",
                "rowHeight": 0.9,
            },
        }
        if description:
            p["description"] = description
        return self._finish(p, x, y, w, h, [target(expr, ref="A")])

    def save(self):
        dash = {
            "annotations": {"list": []},
            "description": self.description,
            "editable": True,
            "fiscalYearStartMonth": 0,
            "graphTooltip": 1,
            "links": [],
            "panels": self.panels,
            "refresh": "30s",
            "schemaVersion": 39,
            "tags": self.tags,
            "templating": {"list": []},
            "time": {"from": "now-1h", "to": "now"},
            "timepicker": {},
            "timezone": "browser",
            "title": self.title,
            "uid": self.uid,
            "version": 1,
            "weekStart": "",
        }
        path = os.path.join(OUT_DIR, f"{self.uid}.json")
        with open(path, "w") as f:
            json.dump(dash, f, indent=1)
            f.write("\n")
        return path, len(self.panels)


def refs(n):
    return [chr(ord("A") + i) for i in range(n)]


# ---------------------------------------------------------------------------
# shared PromQL fragments
# ---------------------------------------------------------------------------

RI = "[$__rate_interval]"
RG = "[$__range]"
QPS = f"sum(rate(res_queries_total{RI}))"

LAT_P = (
    "histogram_quantile({q}, sum by (le) "
    "(rate(res_query_duration_seconds_bucket{ri})))"
)
UP_LAT_P = (
    "histogram_quantile({q}, sum by (upstream, le) "
    "(rate(res_upstream_latency_seconds_bucket{ri})))"
)


# ---------------------------------------------------------------------------
# 1. DNS Service Overview
# ---------------------------------------------------------------------------

def overview():
    d = Dashboard(
        "res-overview",
        "1. DNS Service Overview",
        "What is the DNS service doing right now: request volume and QPS, "
        "success/failure rates, response codes, latency, upstream pool health "
        "and data-plane saturation. All values are live Prometheus series.",
        ["res", "dns", "overview"],
    )

    # KPI row
    d.stat("Query rate (QPS)", QPS, 0, 0, 4, 2, unit="ops", thresholds=GREEN)
    d.stat("Queries in range", f"sum(increase(res_queries_total{RG}))",
           4, 0, 4, 2, unit="short", thresholds=GREEN, instant=True)
    d.stat(
        "NOERROR share of responses",
        'sum(rate(res_response_rcode_total{rcode="NOERROR"}' + RI +
        ")) / sum(rate(res_response_rcode_total" + RI + "))",
        8, 0, 4, 2, unit="percentunit", thresholds=GREEN, decimals=1,
    )
    d.stat("Gateway error rate",
           f"sum(rate(res_query_errors_total{RI}))",
           12, 0, 4, 2, unit="ops", decimals=2,
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 0.1}],
           graph_mode="area")
    d.stat("Latency P95",
           LAT_P.format(q="0.95", ri=RI), 16, 0, 4, 2, unit="s",
           thresholds=GREEN, decimals=3)
    d.stat("Healthy upstreams", "res_healthy_upstreams", 20, 0, 4, 2,
           unit="short", thresholds=[{"color": "red", "value": None},
                                     {"color": "green", "value": 1}])

    # Main charts
    d.timeseries(
        "Query rate by transport (QPS)",
        [
            target(f"sum by (transport) (rate(res_queries_total{RI}))",
                   legend="{{transport}}", ref="A"),
            target(QPS, legend="total", ref="B"),
        ],
        0, 2, 12, 8, unit="ops",
    )
    d.timeseries(
        "Response codes returned to clients",
        [target(f"sum by (rcode) (rate(res_response_rcode_total{RI}))",
                legend="{{rcode}}", ref="A")],
        12, 2, 12, 8, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "End-to-end latency percentiles",
        [target(LAT_P.format(q=q, ri=RI), legend=f"P{p}", ref=r)
         for q, p, r in [("0.5", "50", "A"), ("0.95", "95", "B"), ("0.99", "99", "C")]],
        0, 10, 8, 8, unit="s", thresholds=[
            {"color": "green", "value": None}, {"color": "yellow", "value": 0.1},
            {"color": "orange", "value": 0.5}, {"color": "red", "value": 2},
        ],
    )
    d.timeseries(
        "Gateway errors by reason (rate)",
        [target(f"sum by (reason) (rate(res_query_errors_total{RI}))",
                legend="{{reason}}", ref="A")],
        8, 10, 8, 8, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "Rejections & drops (rate)",
        [
            target(f"rate(res_acl_denied_total{RI})", legend="ACL denied", ref="A"),
            target(f"rate(res_rate_limit_dropped_total{RI})", legend="rate limited", ref="B"),
            target(f"rate(res_overload_dropped_total{RI})", legend="overload", ref="C"),
            target(f"rate(res_malformed_packets_total{RI})", legend="malformed", ref="D"),
            target(f"rate(res_oversized_packets_total{RI})", legend="oversized", ref="E"),
        ],
        16, 10, 8, 8, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "Upstream pool & failovers",
        [
            target("res_healthy_upstreams", legend="healthy upstreams", ref="A"),
            target("res_active_upstreams", legend="active upstreams", ref="B"),
            target(f"60 * rate(res_failovers_total{RI})",
                   legend="failovers / min", ref="C"),
        ],
        0, 18, 12, 8, unit="short", thresholds=[
            {"color": "red", "value": None}, {"color": "green", "value": 1},
        ],
    )
    d.timeseries(
        "Data-plane saturation",
        [
            target("res_udp_inflight", legend="UDP queries in flight", ref="A"),
            target("res_tcp_connections", legend="TCP connections open", ref="B"),
        ],
        12, 18, 12, 8, unit="short",
    )
    return d


# ---------------------------------------------------------------------------
# 2. Client / Traffic Analysis
# ---------------------------------------------------------------------------

def clients():
    d = Dashboard(
        "res-clients",
        "2. Client / Traffic Analysis",
        "Where the traffic comes from: requests per client IP (top-N export, "
        "masked labels by default), top clients by volume/bytes/failures, "
        "per-client outcome rates, rate limiting and ACL activity.",
        ["res", "dns", "clients"],
    )

    d.stat("Clients exported (top-N)", f"count(res_client_queries_total)",
           0, 0, 6, 2, unit="short", thresholds=GREEN, instant=True)
    d.stat("Requests in range", f"sum(increase(res_client_queries_total{RG}))",
           6, 0, 6, 2, unit="short", thresholds=GREEN, instant=True)
    d.stat("Rate-limited in range",
           f"sum(increase(res_rate_limit_dropped_total{RG}))",
           12, 0, 6, 2, unit="short", thresholds=GREEN, instant=True)
    d.stat("ACL denied in range", f"sum(increase(res_acl_denied_total{RG}))",
           18, 0, 6, 2, unit="short", thresholds=GREEN, instant=True)

    d.timeseries(
        "Request rate by client IP (top 10)",
        [target(f"topk(10, sum by (client) (rate(res_client_queries_total{RI})))",
                legend="{{client}}", ref="A")],
        0, 2, 12, 9, unit="ops",
    )
    d.timeseries(
        "Request outcomes (rate, all exported clients)",
        [target(f"sum by (result) (rate(res_client_query_result_total{RI}))",
                legend="{{result}}", ref="A")],
        12, 2, 12, 9, unit="ops", stacked=True, fill=30,
    )

    d.table(
        "Top clients by request volume (range)",
        [target(f"topk(15, sum by (client) (increase(res_client_queries_total{RG})))",
                ref="A", table=True)],
        0, 11, 8, 8,
        renames={"client": "Client", "Value": "Requests"},
        sort_field="Requests", sort_desc=True,
    )
    d.table(
        "Top clients by payload bytes (range)",
        [target(f"topk(15, sum by (client) (increase(res_client_request_bytes_total{RG})))",
                ref="A", table=True)],
        8, 11, 8, 8, unit="bytes",
        renames={"client": "Client", "Value": "Bytes"},
        sort_field="Bytes", sort_desc=True,
    )
    d.table(
        "Top clients by failures & timeouts (range)",
        [target(
            'topk(15, sum by (client) (increase(res_client_query_result_total'
            '{result=~"failed|timeout"}' + RG + ")))",
            ref="A", table=True)],
        16, 11, 8, 8,
        renames={"client": "Client", "Value": "Failures"},
        sort_field="Failures", sort_desc=True,
    )

    d.timeseries(
        "Failures & timeouts per client (top 10, rate)",
        [target(
            'topk(10, sum by (client) (rate(res_client_query_result_total'
            '{result=~"failed|timeout"}' + RI + ")))",
            legend="{{client}}", ref="A")],
        0, 19, 8, 7, unit="ops",
    )
    d.timeseries(
        "Request bytes per client (top 10, rate)",
        [target(f"topk(10, sum by (client) (rate(res_client_request_bytes_total{RI})))",
                legend="{{client}}", ref="A")],
        8, 19, 8, 7, unit="Bps",
    )
    d.timeseries(
        "Rate-limited & ACL-denied per client (rate)",
        [target(
            'sum by (client, result) (rate(res_client_query_result_total'
            '{result=~"rate_limited|acl_denied"}' + RI + "))",
            legend="{{client}} {{result}}", ref="A")],
        16, 19, 8, 7, unit="ops",
    )
    return d


# ---------------------------------------------------------------------------
# 3. Upstream DNS Performance
# ---------------------------------------------------------------------------

def upstreams():
    d = Dashboard(
        "res-upstreams",
        "3. Upstream DNS Performance",
        "Per-upstream view: availability and health state, forwarded requests, "
        "success/failure/timeout rates, latency percentiles, health-check "
        "results, state changes and failovers.",
        ["res", "dns", "upstreams"],
    )

    d.stat("Upstreams UP", "sum(res_upstream_state == 2)",
           0, 0, 4, 2, unit="short",
           thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
           instant=True)
    d.stat("Active upstreams", "res_active_upstreams",
           4, 0, 4, 2, unit="short", thresholds=GREEN, instant=True)
    d.stat("Availability (5m, UP=100%)",
           "100 * avg(avg_over_time(res_upstream_health[5m]))",
           8, 0, 4, 2, unit="percent", decimals=1, thresholds=GREEN)
    d.stat("Forwarded in range", f"sum(increase(res_upstream_queries_total{RG}))",
           12, 0, 4, 2, unit="short", thresholds=GREEN, instant=True)
    d.stat("Failovers in range", f"sum(increase(res_upstream_failovers_total{RG}))",
           16, 0, 4, 2, unit="short",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
           instant=True)
    d.stat("State changes in range",
           f"sum(increase(res_upstream_state_changes_total{RG}))",
           20, 0, 4, 2, unit="short",
           thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 1}],
           instant=True)

    d.timeseries(
        "Forwarded queries per upstream (rate)",
        [target(f"sum by (upstream) (rate(res_upstream_queries_total{RI}))",
                legend="{{upstream}}", ref="A")],
        0, 2, 12, 9, unit="ops",
    )
    d.timeseries(
        "Attempt failures per upstream (rate)",
        [
            target(f"sum by (upstream) (rate(res_upstream_failures_total{RI}))",
                   legend="{{upstream}} — failed", ref="A"),
            target(f"sum by (upstream) (rate(res_upstream_timeouts_total{RI}))",
                   legend="{{upstream}} — timeout", ref="B"),
        ],
        12, 2, 12, 9, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "Answered share of attempts per upstream",
        [
            target(
                f"100 * sum by (upstream) (rate(res_upstream_rcode_total{RI}))"
                f" / sum by (upstream) (rate(res_upstream_queries_total{RI}))",
                legend="{{upstream}}", ref="A"),
        ],
        0, 11, 12, 9, unit="percent", decimals=1, minv=0, maxv=100,
        description="Responses received from the upstream as a share of "
                    "forwarded attempts; gaps (NaN) mean no attempts were "
                    "made — never a fabricated 100%.",
    )
    d.timeseries(
        "Latency per upstream (P50 / P95 / P99)",
        [target(UP_LAT_P.format(q=q, ri=RI), legend=f"{{{{upstream}}}} P{p}", ref=r)
         for q, p, r in [("0.5", "50", "A"), ("0.95", "95", "B"), ("0.99", "99", "C")]],
        12, 11, 12, 9, unit="s", thresholds=[
            {"color": "green", "value": None}, {"color": "yellow", "value": 0.1},
            {"color": "orange", "value": 0.5}, {"color": "red", "value": 2},
        ],
    )

    d.state_timeline(
        "Upstream health state (0=DOWN, 1=DEGRADED, 2=UP)",
        "res_upstream_state", 0, 20, 12, 8,
    )
    d.timeseries(
        "Health-check results (rate)",
        [
            target(f'sum by (upstream) (rate(res_healthcheck_total{{result="success"}}{RI}))',
                   legend="{{upstream}} ok", ref="A"),
            target(f'sum by (upstream) (rate(res_healthcheck_total{{result="failure"}}{RI}))',
                   legend="{{upstream}} fail", ref="B"),
        ],
        12, 20, 6, 8, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "Health-check latency (P95)",
        [target(
            "histogram_quantile(0.95, sum by (upstream, le) "
            f"(rate(res_healthcheck_duration_seconds_bucket{RI})))",
            legend="{{upstream}}", ref="A")],
        18, 20, 6, 8, unit="s",
    )

    d.table(
        "Upstream summary (range)",
        [
            target(f"sum by (upstream) (increase(res_upstream_queries_total{RG}))",
                   ref="A", table=True),
            target(
                f"100 * sum by (upstream) (increase(res_upstream_rcode_total{RG}))"
                f" / sum by (upstream) (increase(res_upstream_queries_total{RG}))",
                ref="B", table=True),
            target(UP_LAT_P.format(q="0.95", ri=RG), ref="C", table=True),
            target(f"sum by (upstream) (increase(res_upstream_failovers_total{RG}))",
                   ref="D", table=True),
            target(f"sum by (upstream) (increase(res_upstream_timeouts_total{RG}))",
                   ref="E", table=True),
        ],
        0, 28, 12, 9, unit="s",
        renames={"upstream": "Upstream", "Value": "Queries", "Value 1": "Answered %",
                 "Value 2": "P95 latency", "Value 3": "Failovers", "Value 4": "Timeouts"},
        description="Queries forwarded, share of attempts answered, P95 "
                    "upstream latency, failovers and timeouts in the selected "
                    "range. Empty columns mean the counter never moved.",
    )
    d.timeseries(
        "Upstream response codes (rate)",
        [target(f"sum by (upstream, rcode) (rate(res_upstream_rcode_total{RI}))",
                legend="{{upstream}} {{rcode}}", ref="A")],
        12, 28, 12, 9, unit="ops", stacked=True, fill=30,
    )

    d.table(
        "Last successful health check (age)",
        [target("time() - res_healthcheck_last_success_timestamp_seconds",
                ref="A", table=True)],
        0, 37, 8, 7, unit="s",
        renames={"upstream": "Upstream", "Value": "Seconds ago"},
        sort_field="Seconds ago", sort_desc=True,
        thresholds=[{"color": "green", "value": None},
                    {"color": "yellow", "value": 60},
                    {"color": "red", "value": 300}],
        description="Seconds since the last successful probe. Missing rows "
                    "mean that upstream has never passed a check.",
    )
    d.timeseries(
        "Failovers per upstream (rate)",
        [target(f"sum by (upstream) (rate(res_upstream_failovers_total{RI}))",
                legend="{{upstream}}", ref="A")],
        8, 37, 8, 7, unit="ops",
    )
    d.timeseries(
        "State changes per upstream (rate)",
        [target(f"sum by (upstream) (rate(res_upstream_state_changes_total{RI}))",
                legend="{{upstream}}", ref="A")],
        16, 37, 8, 7, unit="ops",
    )
    return d


# ---------------------------------------------------------------------------
# 4. Failures & Failover
# ---------------------------------------------------------------------------

def failures():
    d = Dashboard(
        "res-failures",
        "4. Failures & Failover",
        "Everything that goes wrong: gateway errors by reason, client-deadline "
        "timeouts, failovers per upstream, admission drops (ACL, rate limit, "
        "overload), protocol violations and emergency state.",
        ["res", "dns", "failures"],
    )

    d.stat("Gateway errors (range)", f"sum(increase(res_query_errors_total{RG}))",
           0, 0, 4, 2, unit="short",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
           instant=True)
    d.stat("Deadline timeouts (range)",
           f'sum(increase(res_query_errors_total{{reason="deadline"}}{RG}))',
           4, 0, 4, 2, unit="short",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
           instant=True)
    d.stat("Failovers (range)", f"sum(increase(res_failovers_total{RG}))",
           8, 0, 4, 2, unit="short",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
           instant=True)
    d.stat("Rate-limited (range)", f"sum(increase(res_rate_limit_dropped_total{RG}))",
           12, 0, 4, 2, unit="short", thresholds=GREEN, instant=True)
    d.stat("ACL denied (range)", f"sum(increase(res_acl_denied_total{RG}))",
           16, 0, 4, 2, unit="short", thresholds=GREEN, instant=True)
    d.stat("Malformed packets (range)", f"sum(increase(res_malformed_packets_total{RG}))",
           20, 0, 4, 2, unit="short", thresholds=GREEN, instant=True)

    d.timeseries(
        "Gateway errors by reason (rate)",
        [target(f"sum by (reason) (rate(res_query_errors_total{RI}))",
                legend="{{reason}}", ref="A")],
        0, 2, 12, 8, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "Error responses to clients (rate)",
        [target(
            'sum by (rcode) (rate(res_response_rcode_total'
            '{rcode=~"SERVFAIL|REFUSED|FORMERR|NOTIMP"}' + RI + "))",
            legend="{{rcode}}", ref="A")],
        12, 2, 12, 8, unit="ops", stacked=True, fill=30,
    )

    d.timeseries(
        "Failovers per minute",
        [
            target(f"60 * sum by (upstream) (rate(res_upstream_failovers_total{RI}))",
                   legend="{{upstream}}", ref="A"),
            target(f"60 * rate(res_failovers_total{RI})",
                   legend="all upstreams", ref="B"),
        ],
        0, 10, 8, 8, unit="ops", decimals=2,
    )
    d.timeseries(
        "Upstream attempt failures (rate)",
        [
            target(f"sum by (upstream) (rate(res_upstream_failures_total{RI}))",
                   legend="{{upstream}} — failed", ref="A"),
            target(f"sum by (upstream) (rate(res_upstream_timeouts_total{RI}))",
                   legend="{{upstream}} — timeout", ref="B"),
        ],
        8, 10, 8, 8, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "Admission drops (rate)",
        [
            target(f"rate(res_acl_denied_total{RI})", legend="ACL denied", ref="A"),
            target(f"rate(res_rate_limit_dropped_total{RI})", legend="rate limited", ref="B"),
            target(f"rate(res_overload_dropped_total{RI})", legend="overload", ref="C"),
        ],
        16, 10, 8, 8, unit="ops", stacked=True, fill=30,
    )

    d.timeseries(
        "Protocol violations (rate)",
        [
            target(f"rate(res_malformed_packets_total{RI})", legend="malformed", ref="A"),
            target(f"rate(res_oversized_packets_total{RI})", legend="oversized", ref="B"),
            target(f"rate(res_tcp_connections_rejected_total{RI})",
                   legend="TCP rejected", ref="C"),
        ],
        0, 18, 8, 8, unit="ops", stacked=True, fill=30,
    )
    d.table(
        "Top failing clients (range)",
        [target(
            'topk(15, sum by (client) (increase(res_client_query_result_total'
            '{result=~"failed|timeout"}' + RG + ")))",
            ref="A", table=True)],
        8, 18, 8, 8,
        renames={"client": "Client", "Value": "Failures"},
        sort_field="Failures", sort_desc=True,
    )
    d.timeseries(
        "Operational counters (rate)",
        [
            target(f"sum(rate(res_upstream_state_changes_total{RI}))",
                   legend="upstream state changes", ref="A"),
            target(f"rate(res_config_reloads_total{RI})",
                   legend="config reloads", ref="B"),
            target(f"rate(res_config_errors_total{RI})",
                   legend="config errors", ref="C"),
        ],
        16, 18, 8, 8, unit="ops", decimals=3,
    )

    d.stat(
        "Emergency (all upstreams down)",
        "(sum(res_active_upstreams) > bool 0) * (sum(res_healthy_upstreams) == bool 0)",
        0, 26, 4, 4, unit="short", instant=True,
        mappings=[{"type": "value", "options": {
            "0": {"text": "OK", "color": "green"},
            "1": {"text": "EMERGENCY", "color": "red"}}}],
        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
        description="1 when at least one upstream is configured but none is UP "
                    "(clients are receiving SERVFAIL).",
    )
    d.stat("Unhealthy upstreams", "sum(res_active_upstreams) - sum(res_healthy_upstreams)",
           4, 26, 4, 4, unit="short", instant=True,
           thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 1},
                       {"color": "red", "value": 3}])
    d.table(
        "Gateway error reasons (range)",
        [target(f"sum by (reason) (increase(res_query_errors_total{RG}))",
                ref="A", table=True)],
        8, 26, 16, 4,
        renames={"reason": "Reason", "Value": "Count"},
        sort_field="Count", sort_desc=True,
    )
    return d


# ---------------------------------------------------------------------------
# 5. Packet & Protocol Analysis
# ---------------------------------------------------------------------------

def packets():
    d = Dashboard(
        "res-packets",
        "5. Packet & Protocol Analysis",
        "Wire-level accounting: UDP packet counts and rates, request/response "
        "payload sizes including the largest observed packet, UDP vs TCP "
        "distribution, connection handling and packet-level drops.",
        ["res", "dns", "packets"],
    )

    d.stat("Packets in / s", f"sum(rate(res_udp_packets_received_total{RI}))",
           0, 0, 4, 2, unit="ops", decimals=2, thresholds=GREEN, graph_mode="area")
    d.stat("Packets out / s", f"sum(rate(res_udp_packets_sent_total{RI}))",
           4, 0, 4, 2, unit="ops", decimals=2, thresholds=GREEN, graph_mode="area")
    d.stat("Payload in / s", f"sum(rate(res_request_bytes_total{RI}))",
           8, 0, 4, 2, unit="Bps", thresholds=GREEN, graph_mode="area")
    d.stat("Payload out / s", f"sum(rate(res_response_bytes_total{RI}))",
           12, 0, 4, 2, unit="Bps", thresholds=GREEN, graph_mode="area")
    d.stat("Largest request seen", "res_max_request_bytes",
           16, 0, 4, 2, unit="bytes", thresholds=GREEN, instant=True)
    d.stat("Largest response seen", "res_max_response_bytes",
           20, 0, 4, 2, unit="bytes", thresholds=GREEN, instant=True)

    d.timeseries(
        "UDP packet rates",
        [
            target(f"sum(rate(res_udp_packets_received_total{RI}))",
                   legend="received / s", ref="A"),
            target(f"sum(rate(res_udp_packets_sent_total{RI}))",
                   legend="sent / s", ref="B"),
        ],
        0, 2, 12, 8, unit="ops",
    )
    d.timeseries(
        "Payload byte rates",
        [
            target(f"sum(rate(res_request_bytes_total{RI}))",
                   legend="request bytes / s", ref="A"),
            target(f"sum(rate(res_response_bytes_total{RI}))",
                   legend="response bytes / s", ref="B"),
        ],
        12, 2, 12, 8, unit="Bps",
    )

    d.timeseries(
        "UDP vs TCP query rate",
        [target(f"sum by (transport) (rate(res_queries_total{RI}))",
                legend="{{transport}}", ref="A")],
        0, 10, 8, 7, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "UDP vs TCP share of traffic",
        [
            target(f'100 * sum(rate(res_queries_total{{transport="udp"}}{RI}))'
                   f" / sum(rate(res_queries_total{RI}))",
                   legend="UDP %", ref="A"),
            target(f'100 * sum(rate(res_queries_total{{transport="tcp"}}{RI}))'
                   f" / sum(rate(res_queries_total{RI}))",
                   legend="TCP %", ref="B"),
        ],
        8, 10, 8, 7, unit="percent", minv=0, maxv=100,
    )
    d.timeseries(
        "TCP connections",
        [
            target(f"sum(rate(res_tcp_connections_total{RI}))",
                   legend="accepted / s", ref="A"),
            target("res_tcp_connections", legend="open", ref="B"),
            target(f"sum(rate(res_tcp_connections_rejected_total{RI}))",
                   legend="rejected / s", ref="C"),
        ],
        16, 10, 8, 7, unit="ops", decimals=2,
    )

    d.timeseries(
        "Average payload per query",
        [
            target(f"sum(rate(res_request_bytes_total{RI}))"
                   f" / sum(rate(res_queries_total{RI}))",
                   legend="request bytes", ref="A"),
            target(f"sum(rate(res_response_bytes_total{RI}))"
                   f" / sum(rate(res_queries_total{RI}))",
                   legend="response bytes", ref="B"),
        ],
        0, 17, 8, 7, unit="bytes", decimals=1,
    )
    d.timeseries(
        "Largest observed payload (running maximum)",
        [
            target("res_max_request_bytes", legend="request", ref="A"),
            target("res_max_response_bytes", legend="response", ref="B"),
        ],
        8, 17, 8, 7, unit="bytes",
    )
    d.timeseries(
        "UDP queries in flight",
        [target("res_udp_inflight", legend="in flight", ref="A")],
        16, 17, 8, 7, unit="short",
    )

    d.timeseries(
        "Packet-level drops (rate)",
        [
            target(f"rate(res_oversized_packets_total{RI})",
                   legend="oversized (over max_udp_packet_size)", ref="A"),
            target(f"rate(res_malformed_packets_total{RI})",
                   legend="malformed (unparseable)", ref="B"),
        ],
        0, 24, 12, 8, unit="ops", stacked=True, fill=30,
    )
    d.bargauge(
        "Question types (range, top 12)",
        [target(f"topk(12, sum by (qtype) (increase(res_query_type_total{RG})))",
                ref="A", instant=True)],
        12, 24, 12, 8, unit="short",
    )
    return d


# ---------------------------------------------------------------------------
# 6. Detailed DNS Analytics
# ---------------------------------------------------------------------------

def analytics():
    d = Dashboard(
        "res-analytics",
        "6. Detailed DNS Analytics",
        "Deep dive: response-code and question-type distributions, latency "
        "histogram and percentiles, cache behaviour, client outcome mix and "
        "received/answered/forwarded accounting.",
        ["res", "dns", "analytics"],
    )

    d.timeseries(
        "Response codes over time (rate)",
        [target(f"sum by (rcode) (rate(res_response_rcode_total{RI}))",
                legend="{{rcode}}", ref="A")],
        0, 0, 8, 8, unit="ops", stacked=True, fill=30,
    )
    d.timeseries(
        "Question types over time (top 8)",
        [target(f"topk(8, sum by (qtype) (rate(res_query_type_total{RI})))",
                legend="{{qtype}}", ref="A")],
        8, 0, 8, 8, unit="ops", stacked=True, fill=30,
    )
    d.bargauge(
        "Response code distribution (range, %)",
        [target(
            f"100 * sum by (rcode) (increase(res_response_rcode_total{RG}))"
            f" / sum(increase(res_response_rcode_total{RG}))",
            ref="A", instant=True)],
        16, 0, 8, 8, unit="percent", maxv=100, decimals=1,
    )

    d.heatmap(
        "End-to-end latency distribution",
        f"sum by (le) (rate(res_query_duration_seconds_bucket{RI}))",
        0, 8, 12, 8,
    )
    d.timeseries(
        "Latency percentiles & mean",
        [target(LAT_P.format(q=q, ri=RI), legend=f"P{p}", ref=r)
         for q, p, r in [("0.5", "50", "A"), ("0.95", "95", "B"), ("0.99", "99", "C")]]
        + [
            target(f"rate(res_query_duration_seconds_sum{RI})"
                   f" / rate(res_query_duration_seconds_count{RI})",
                   legend="mean", ref="D"),
        ],
        12, 8, 12, 8, unit="s",
    )

    d.timeseries(
        "Cache hit & miss rates",
        [
            target(f"sum(rate(res_cache_hits_total{RI}))", legend="hits", ref="A"),
            target(f"sum(rate(res_cache_misses_total{RI}))", legend="misses", ref="B"),
        ],
        0, 16, 12, 7, unit="ops", stacked=True, fill=30,
        description="No data while caching is disabled — a real gap, not a zero.",
    )
    d.stat(
        "Cache hit ratio",
        f"sum(rate(res_cache_hits_total{RI}))"
        f" / (sum(rate(res_cache_hits_total{RI}))"
        f" + sum(rate(res_cache_misses_total{RI})))",
        12, 16, 6, 7, unit="percentunit", decimals=1, thresholds=GREEN,
        description="No data while caching is disabled.",
    )
    d.stat("Cache entries", "res_cache_entries", 18, 16, 6, 7,
           unit="short", thresholds=GREEN)

    d.table(
        "Client outcomes (range)",
        [target(f"sum by (result) (increase(res_client_query_result_total{RG}))",
                ref="A", table=True)],
        0, 23, 12, 8,
        renames={"result": "Outcome", "Value": "Count"},
        sort_field="Count", sort_desc=True,
    )
    d.table(
        "Gateway error reasons (range)",
        [target(f"sum by (reason) (increase(res_query_errors_total{RG}))",
                ref="A", table=True)],
        12, 23, 12, 8,
        renames={"reason": "Reason", "Value": "Count"},
        sort_field="Count", sort_desc=True,
    )

    d.timeseries(
        "Received vs answered vs forwarded (rate)",
        [
            target(f"sum(rate(res_queries_total{RI}))",
                   legend="received", ref="A"),
            target(f"sum(rate(res_response_rcode_total{RI}))",
                   legend="answered", ref="B"),
            target(f"sum(rate(res_upstream_queries_total{RI}))",
                   legend="forwarded attempts", ref="C"),
        ],
        0, 31, 12, 7, unit="ops",
        description="Received minus answered shows drops; forwarded above "
                    "received shows retries/failovers.",
    )
    d.table(
        "Protocol rejects (range)",
        [target(
            f'label_replace(increase(res_malformed_packets_total{RG}), '
            f'"kind", "malformed", "", "") or '
            f'label_replace(increase(res_oversized_packets_total{RG}), '
            f'"kind", "oversized", "", "") or '
            f'label_replace(increase(res_tcp_connections_rejected_total{RG}), '
            f'"kind", "tcp_rejected", "", "") or '
            f'label_replace(increase(res_overload_dropped_total{RG}), '
            f'"kind", "overload", "", "")',
            ref="A", table=True)],
        12, 31, 12, 7,
        renames={"kind": "Kind", "Value": "Count"},
        sort_field="Count", sort_desc=True,
    )
    return d


# ---------------------------------------------------------------------------

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    total = 0
    for build in (overview, clients, upstreams, failures, packets, analytics):
        d = build()
        path, n = d.save()
        total += n
        print(f"wrote {path} ({n} panels)")
    print(f"{total} panels total")


if __name__ == "__main__":
    main()
