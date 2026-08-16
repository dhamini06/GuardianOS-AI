import { useMemo } from "react";
import Chart from "react-apexcharts";
import type { ThreatReport } from "../../api/types";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

/**
 * Detection timeline: counts of flagged reports bucketed per minute, split by
 * severity. Built purely from real report timestamps.
 */
export function EventChart({ threats }: { threats: ThreatReport[] }) {
  const series = useMemo<{
    categories: string[];
    data: number[][];
    bucketMs: number;
  } | null>(() => {
    if (threats.length === 0) return null;
    const min = Math.floor(Math.min(...threats.map((t) => t.timestamp)) / 60) * 60;
    const max = Math.ceil(Math.max(...threats.map((t) => t.timestamp)) / 60) * 60;
    const bucketMs = 60_000;
    const buckets = Math.max(1, Math.round((max - min) / 60));

    const counts: number[][] = SEVERITIES.map(() => new Array(buckets).fill(0));
    for (const t of threats) {
      const idx = Math.min(buckets - 1, Math.floor((t.timestamp - min) / 60));
      const sev = SEVERITIES.indexOf(t.detection.severity as (typeof SEVERITIES)[number]);
      if (sev >= 0) counts[sev][idx] += 1;
    }

    return {
      categories: Array.from({ length: buckets }, (_, i) => {
        const d = new Date((min + i * 60) * 1000);
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      }),
      data: counts,
      bucketMs,
    };
  }, [threats]);

  if (!series) {
    return null;
  }

  const colors = SEVERITIES.map((s) => {
    switch (s) {
      case "critical":
        return "#f04438";
      case "high":
        return "#fd853a";
      case "medium":
        return "#fdb022";
      default:
        return "#0ba5ec";
    }
  });

  return (
    <Chart
      type="bar"
      height={220}
      options={{
        chart: {
          stacked: true,
          toolbar: { show: false },
          fontFamily: "Outfit, sans-serif",
          foreColor: "#98a2b3",
        },
        plotOptions: {
          bar: { columnWidth: "60%", borderRadius: 2 },
        },
        colors,
        xaxis: {
          categories: series.categories,
          labels: { style: { fontSize: "11px" } },
        },
        yaxis: {
          title: { text: "detections" },
          labels: { style: { fontSize: "11px" } },
        },
        legend: { position: "bottom" },
        dataLabels: { enabled: false },
        grid: { borderColor: "#e4e7ec" },
        noData: { text: "No detections" },
      }}
      series={SEVERITIES.map((s, i) => ({ name: s, data: series.data[i] }))}
    />
  );
}

export function severityToneHex(severity: string): string {
  switch (severity) {
    case "critical":
      return "#f04438";
    case "high":
      return "#fd853a";
    case "medium":
      return "#fdb022";
    case "low":
      return "#0ba5ec";
    default:
      return "#98a2b3";
  }
}
