/* SteelOS installer — palette and metrics.
 *
 * One place, because the colours carry meaning and a second definition that
 * drifts would make them lie. The accent is used for exactly one thing: what
 * is selected, or what is currently true. Caution and danger are used for
 * choices that trade away protection or that can destroy data — never for
 * emphasis.
 */
import QtQuick

QtObject {
    readonly property color background:    "#0E1216"
    readonly property color surface:       "#1B222A"
    readonly property color surfaceHover:  "#222B34"
    readonly property color border:        "#28313B"
    readonly property color borderStrong:  "#3A4652"

    readonly property color text:          "#E6EAEE"
    readonly property color textMuted:     "#93A1AE"
    readonly property color textFaint:     "#66727E"

    readonly property color accent:        "#5AA2C8"
    readonly property color accentWash:    "#16303D"
    readonly property color caution:       "#E0A33E"
    readonly property color danger:        "#D9634B"
    readonly property color ok:            "#6FBF73"

    readonly property int   gap:           12
    readonly property int   gapLarge:      20
    readonly property int   radius:        6
    readonly property int   titleSize:     20
    readonly property int   bodySize:      13
    readonly property int   smallSize:     12
}
