/* The bridge between the pages and the jobs.
 *
 * Every page writes one map into Calamares' global storage under a `steelos.*`
 * key, and the Python job modules read exactly those keys. Nothing else passes
 * between the UI and the install: no files, no environment, no second copy of a
 * decision that could disagree with the first.
 *
 * `valid` gates the Next button, through the `config` object the steelospage
 * view module exposes. It cannot be done from QML alone: Calamares'
 * ViewManager::updateNextStatus() starts with a qobject_cast on sender(), so a
 * direct call from QML is silently a no-op, and next() re-reads the step's
 * isNextEnabled() after activating it anyway. See calamares/viewmodule.
 */
import QtQuick
import io.calamares.core 1.0

QtObject {
    id: state

    /** Global-storage key this page owns, e.g. "steelos.hardening". */
    property string key: ""

    /** Page contents. Assign a whole object; `commit()` writes it. */
    property var values: ({})

    /** Whether the page is complete enough to move on from. */
    property bool valid: true

    onValidChanged: applyGate()

    function commit() {
        if (key.length > 0) {
            Global.insert(key, values);
        }
    }

    /** Merge a partial update, write it through, and re-check the gate. */
    function set(patch) {
        var merged = {};
        for (var a in values) {
            merged[a] = values[a];
        }
        for (var b in patch) {
            merged[b] = patch[b];
        }
        values = merged;
        commit();
    }

    function load(defaults) {
        var stored = Global.contains(key) ? Global.value(key) : null;
        if (stored && typeof stored === "object") {
            var merged = {};
            for (var a in defaults) {
                merged[a] = defaults[a];
            }
            for (var b in stored) {
                merged[b] = stored[b];
            }
            values = merged;
        } else {
            values = defaults;
        }
        commit();
    }

    function applyGate() {
        // `config` is the page's SteelPageConfig, set as a context property by
        // QmlViewStep before the QML is created.
        config.valid = state.valid;
    }

    Component.onCompleted: applyGate()
}
