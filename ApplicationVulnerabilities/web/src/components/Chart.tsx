import ReactECharts from 'echarts-for-react'
import type { EChartsOption } from 'echarts'
import { chartTokens, useTheme } from '@/lib/theme'

type Tokens = (typeof chartTokens)['light'] | (typeof chartTokens)['dark']

/** ECharts with the portal's light/dark chart chrome applied; `build` receives the active tokens. */
// build returns a plain ECharts option object; typed loosely so tooltip formatters can name their own params
type AnySeries = Record<string, unknown> & { type?: string; itemStyle?: Record<string, unknown>; lineStyle?: Record<string, unknown>; areaStyle?: unknown; color?: unknown }

/** Shared polish for every chart: rounded bars, smooth lines with a colour fade underneath, a slower eased entrance.
    A chart that sets these itself keeps its own values. */
function polish(series: unknown, t: Tokens): unknown {
  const list = Array.isArray(series) ? series : series ? [series] : []
  const out = list.map((raw, i) => {
    const s = { ...(raw as AnySeries) }
    if (s.type === 'bar') {
      s.itemStyle = { borderRadius: [6, 6, 2, 2], ...(s.itemStyle ?? {}) }
      if (s.barMaxWidth === undefined) s.barMaxWidth = 34
    }
    if (s.type === 'line') {
      if (s.smooth === undefined) s.smooth = 0.4
      const colour = (s.lineStyle?.color ?? s.itemStyle?.color ?? s.color ?? t.series[i % t.series.length]) as string
      s.lineStyle = { width: 2.5, ...(s.lineStyle ?? {}) }
      if (s.areaStyle === undefined && typeof colour === 'string' && colour.startsWith('#')) {
        s.areaStyle = { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: colour + '55' }, { offset: 1, color: colour + '00' }] } }
      }
    }
    if (s.type === 'pie' && s.itemStyle === undefined) s.itemStyle = { borderRadius: 4, borderColor: t.surface, borderWidth: 2 }
    return s
  })
  return Array.isArray(series) ? out : out[0]
}

export function Chart({ build, height = 240 }: { build: (t: Tokens) => object; height?: number }) {
  const { theme } = useTheme()
  const t = chartTokens[theme]
  const base: EChartsOption = {
    backgroundColor: 'transparent',
    color: [...t.series],
    animationDuration: 900,
    animationEasing: 'cubicOut',
    animationDelayUpdate: (i: number) => i * 20,
    textStyle: { color: t.ink2, fontFamily: 'Inter Variable, system-ui, sans-serif' },
    tooltip: {
      backgroundColor: t.surface,
      borderColor: t.axis,
      textStyle: { color: t.ink, fontSize: 12 },
      extraCssText: 'box-shadow: 0 8px 24px rgba(0,0,0,.28); border-radius: 10px; padding: 8px 12px;',
    },
  }
  const own = build(t) as EChartsOption
  // keep the shared tooltip look even when a chart sets its own tooltip behaviour
  const tooltip = own.tooltip && !Array.isArray(own.tooltip) ? { ...(base.tooltip as object), ...own.tooltip } : base.tooltip
  return (
    <ReactECharts
      key={theme}
      option={{ ...base, ...own, tooltip, series: polish(own.series, t) as EChartsOption['series'] }}
      style={{ height, width: '100%' }}
      notMerge
      opts={{ renderer: 'svg' }}
    />
  )
}

export const axisStyle = (t: Tokens) => ({
  axisLine: { lineStyle: { color: t.axis } },
  axisTick: { show: false },
  axisLabel: { color: t.muted, fontSize: 11 },
  splitLine: { lineStyle: { color: t.grid, type: 'dashed' as const } },
})
