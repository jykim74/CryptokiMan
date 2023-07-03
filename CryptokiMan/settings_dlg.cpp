#include <QtGlobal>
#include <QtWidgets>

#include "i18n_helper.h"
#include "settings_dlg.h"
#include "ui_settings_dlg.h"
#include "man_applet.h"
#include "auto_update_service.h"
#include "settings_mgr.h"
#include "mainwindow.h"
#include "common.h"

SettingsDlg::SettingsDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mLangCombo->addItems(I18NHelper::getInstance()->getLanguages());

    initFontFamily();
    initialize();
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    mgr->setSaveLibPath( mSaveLibPathCheck->checkState() == Qt::Checked );

    if( manApplet->isLicense() )
    {
        mgr->setShowLogTab( mShowLogTabCheck->checkState() == Qt::Checked );
        manApplet->mainWindow()->logView( mShowLogTabCheck->checkState() == Qt::Checked );
    }

    mgr->setLogLevel( mLogLevelCombo->currentIndex() );
    mgr->setFileReadSize( mFileReadSizeText->text().toInt() );
    mgr->setUseDeviceMech( mUseDeviceMechCheck->isChecked() );

    mgr->setFontFamily( mFontFamilyCombo->currentText() );

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

void SettingsDlg::initFontFamily()
{
    QFontDatabase fontDB;
    QStringList fontList = fontDB.families();
    mFontFamilyCombo->addItems( fontList );
}

void SettingsDlg::initialize()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    Qt::CheckState state;

    state = mgr->saveLibPath() ? Qt::Checked : Qt::Unchecked;
    mSaveLibPathCheck->setCheckState(state);

    if( manApplet->isLicense() )
    {
        state = mgr->showLogTab() ? Qt::Checked : Qt::Unchecked;
        mShowLogTabCheck->setCheckState(state);
    }
    else
        mShowLogTabCheck->hide();

#ifdef _AUTO_UPDATE
    if( AutoUpdateService::instance()->shouldSupportAutoUpdate()) {
        state = AutoUpdateService::instance()->autoUpdateEnabled() ? Qt::Checked : Qt::Unchecked;
        mCheckLatestVersionCheck->setCheckState(state);
    }
#else
    mCheckLatestVersionCheck->hide();
#endif

    mLogLevelCombo->addItems( kLogLevel );
    mLogLevelCombo->setCurrentIndex( mgr->getLogLevel() );

    QIntValidator *intVal = new QIntValidator( 0, 999999 );
    mFileReadSizeText->setValidator( intVal );
    mFileReadSizeText->setText( QString("%1").arg(mgr->getFileReadSize()));

    mUseDeviceMechCheck->setChecked( mgr->getUseDeviceMech() );
    mFontFamilyCombo->setCurrentText( mgr->getFontFamily() );

    mLangCombo->setCurrentIndex(I18NHelper::getInstance()->preferredLanguage());
    tabWidget->setCurrentIndex(0);
}
