/* SteelOS installer page — a QML view step that can refuse to go forward.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Why this exists rather than reusing Calamares' `notesqml`.
 *
 * The SteelOS pages collect input that later jobs will act on irreversibly: a
 * target disk, a passphrase, a recovery-key confirmation, a comprehension check
 * covering things that destroy data. A page that is not filled in must not be
 * possible to walk past.
 *
 * QML cannot express that on its own. Calamares gates the Next button through
 * ViewManager::updateNextStatus(), which begins with
 *
 *     ViewStep* vs = qobject_cast< ViewStep* >( sender() );
 *
 * so it only does anything when it is invoked as a slot connected to a
 * ViewStep's nextStatusChanged signal. Called directly from QML, sender() is
 * null and the call silently does nothing. Worse, ViewManager::next() sets the
 * button from the incoming step's isNextEnabled() *after* calling onActivate(),
 * so even a gate applied at the right moment is overwritten a few lines later.
 *
 * The fix is a view step that owns a `valid` flag: QML writes it, the step
 * emits nextStatusChanged, and isNextEnabled() reports it. That is all this
 * module is. Everything else — the pages, the palette, the wording — stays in
 * QML in the branding directory, where it can be read and changed without a
 * compiler.
 */

#ifndef STEELPAGEVIEWSTEP_H
#define STEELPAGEVIEWSTEP_H

#include "DllMacro.h"
#include "locale/TranslatableConfiguration.h"
#include "utils/PluginFactory.h"
#include "viewpages/QmlViewStep.h"

#include <QObject>
#include <QVariantMap>

/** @brief The object QML sees as `config`. */
class SteelPageConfig : public QObject
{
    Q_OBJECT

    /** @brief Whether the page has enough input to move on from.
     *
     * Defaults to true so a page that never sets it behaves like an ordinary
     * informational step. Pages that require input set it false immediately.
     */
    Q_PROPERTY( bool valid READ isValid WRITE setValid NOTIFY validChanged )

public:
    explicit SteelPageConfig( QObject* parent = nullptr );

    bool isValid() const { return m_valid; }
    void setValid( bool valid );

signals:
    void validChanged( bool valid );

private:
    bool m_valid = true;
};

class PLUGINDLLEXPORT SteelPageViewStep : public Calamares::QmlViewStep
{
    Q_OBJECT

public:
    explicit SteelPageViewStep( QObject* parent = nullptr );
    ~SteelPageViewStep() override;

    QString prettyName() const override;
    bool isNextEnabled() const override;

    void setConfigurationMap( const QVariantMap& configurationMap ) override;

protected:
    QObject* getConfig() override;

private:
    SteelPageConfig* m_config;
    Calamares::Locale::TranslatedString* m_label = nullptr;
};

CALAMARES_PLUGIN_FACTORY_DECLARATION( SteelPageViewStepFactory )

#endif
