#include <QtGlobal>
#include <QtWidgets>

#include "i18n_helper.h"
#include "settings_dlg.h"
#include "ui_settings_dlg.h"
#include "man_applet.h"
#include "auto_update_service.h"
#include "settings_mgr.h"

SettingsDlg::SettingsDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mLangCombo->addItems(I18NHelper::getInstance()->getLanguages());

    initialize();
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    mgr->setSaveLibPath( mSaveLibPathCheck->checkState() == Qt::Checked );
    mgr->setShowLogWindow( mShowLogWindowCheck->checkState() == Qt::Checked );

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate() ) {
        bool enabled = mCheckLatestVersionCheck->checkState() == Qt::Checked;
        AutoUpdateService::instance()->setAutoUpdateEnabled(enabled);
    }
#endif

    bool language_changed = false;

    if( mLangCombo->currentIndex() != I18NHelper::getInstance()->preferredLanguage() )
    {
        language_changed = true;
        I18NHelper::getInstance()->setPreferredLanguage(mLangCombo->currentIndex());
    }

    if( language_changed && manApplet->yesOrNoBox(tr("You have changed language. Restart to apply it?"), this, true))
        manApplet->restartApp();
}

void SettingsDlg::accept()
{
    updateSettings();
    QDialog::accept();
}


void SettingsDlg::initialize()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    Qt::CheckState state;

    state = mgr->saveLibPath() ? Qt::Checked : Qt::Unchecked;
    mSaveLibPathCheck->setCheckState(state);

    state = mgr->showLogWindow() ? Qt::Checked : Qt::Unchecked;
    mShowLogWindowCheck->setCheckState(state);

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate()) {
        state = AutoUpdateService::instance()->autoUpdateEnabled() ? Qt::Checked : Qt::Unchecked;
        mCheckLatestVersionCheck->setCheckState(state);
    }
#endif

    mLangCombo->setCurrentIndex(I18NHelper::getInstance()->preferredLanguage());
}
