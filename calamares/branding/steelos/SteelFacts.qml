/* Reads the machine facts that steelos-live-probe collected at boot.
 *
 * The installer UI never runs a process. Everything it knows about the hardware
 * comes from this one file, written once by a script that can be audited on its
 * own — and the same file is read by the install jobs, so the UI cannot promise
 * something the jobs will then decide differently.
 *
 * If the probe did not run (a developer running the installer outside the live
 * medium), `loaded` stays false and pages fall back to asking rather than
 * asserting.
 */
import QtQuick

QtObject {
    id: facts

    property bool loaded: false
    property var data: ({})
    property string recoveryKey: ""

    readonly property string statePath: "file:///run/steelos"

    readonly property string firmware: data.firmware || "unknown"
    readonly property string secureBoot: data.secureBoot || "unknown"
    readonly property bool setupMode: data.setupMode === true
    readonly property string tpm: data.tpm || "none"
    readonly property bool hasTpm2: tpm === "tpm2"
    readonly property string gpuVendor: data.gpuVendor || "other"
    readonly property bool memoryEncryptionSupported: data.memoryEncryptionSupported === true
    readonly property bool memoryEncryptionActive: data.memoryEncryptionActive === true
    readonly property bool iommu: data.iommu === true
    readonly property bool network: data.network === true
    readonly property var disks: data.disks || []
    readonly property real minimumDiskBytes: data.minimumDiskBytes || 68719476736

    function readFile(url, onDone) {
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                onDone(xhr.status === 200 || xhr.status === 0 ? xhr.responseText : "");
            }
        };
        try {
            xhr.open("GET", url);
            xhr.send();
        } catch (e) {
            onDone("");
        }
    }

    function load() {
        readFile(statePath + "/hardware.json", function(body) {
            if (body.length > 0) {
                try {
                    facts.data = JSON.parse(body);
                    facts.loaded = true;
                } catch (e) {
                    facts.loaded = false;
                }
            }
        });
        readFile(statePath + "/recovery-key", function(body) {
            facts.recoveryKey = body.trim();
        });
    }

    Component.onCompleted: load()
}
