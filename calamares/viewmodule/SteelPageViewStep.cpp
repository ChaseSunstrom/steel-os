/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "SteelPageViewStep.h"

#include "utils/Variant.h"

SteelPageConfig::SteelPageConfig( QObject* parent )
    : QObject( parent )
{
}

void
SteelPageConfig::setValid( bool valid )
{
    if ( m_valid == valid )
    {
        return;
    }
    m_valid = valid;
    emit validChanged( m_valid );
}

SteelPageViewStep::SteelPageViewStep( QObject* parent )
    : Calamares::QmlViewStep( parent )
    , m_config( new SteelPageConfig( this ) )
{
    // The signal is what makes this work at all: ViewManager's slot checks
    // sender(), so the notification has to come from the ViewStep rather than
    // from QML calling the slot directly.
    connect( m_config,
             &SteelPageConfig::validChanged,
             this,
             [ this ]( bool valid ) { emit nextStatusChanged( valid ); } );
}

SteelPageViewStep::~SteelPageViewStep() {}

QObject*
SteelPageViewStep::getConfig()
{
    return m_config;
}

bool
SteelPageViewStep::isNextEnabled() const
{
    // ViewManager::next() re-reads this after activating the step, which is
    // exactly why the flag has to live here and not in QML.
    return m_config->isValid();
}

QString
SteelPageViewStep::prettyName() const
{
    return m_label ? m_label->get() : tr( "SteelOS" );
}

void
SteelPageViewStep::setConfigurationMap( const QVariantMap& configurationMap )
{
    bool labelMapOk = false;
    const auto labels = Calamares::getSubMap( configurationMap, "qmlLabel", labelMapOk );
    if ( labelMapOk && labels.contains( "name" ) )
    {
        m_label = new Calamares::Locale::TranslatedString( labels, "name" );
    }

    // Parent last: it loads the QML, and the QML expects `config` to exist.
    Calamares::QmlViewStep::setConfigurationMap( configurationMap );
}

CALAMARES_PLUGIN_FACTORY_DEFINITION( SteelPageViewStepFactory,
                                     registerPlugin< SteelPageViewStep >(); )
