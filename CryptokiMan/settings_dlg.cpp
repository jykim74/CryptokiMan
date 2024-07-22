/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
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
#include "mech_mgr.h"

SettingsDlg::SettingsDlg(QWidget *parent) :
    QDialog(parent)
{
    setupUi(this);

    mLangCombo->addItems(I18NHelper::getInstance()->getLanguages());

    initFontFamily();
    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif
    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

SettingsDlg::~SettingsDlg()
{

}

void SettingsDlg::updateSettings()
{
    SettingsMgr *mgr = manApplet->settingsMgr();

    if( manApplet->isLicense() )
    {
        mgr->setUseLogTab( mUseLogTabCheck->checkState() == Qt::Checked );
        manApplet->mainWindow()->useLog( mUseLogTabCheck->checkState() == Qt::Checked );

        if( mUseDeviceMechCheck->isChecked() )
        {
            MechMgr* mechMgr = manApplet->mechMgr();
            mechMgr->loadMechList();
        }

        mgr->setFileReadSize( mFileReadSizeText->text().toInt() );
        mgr->setLogLevel( mLogLevelCombo->currentIndex() );
    }

    mgr->setFindMaxObjectsCount( mFindMaxObjectsCountText->text().toInt() );
    mgr->setUseDeviceMech( mUseDeviceMechCheck->isChecked() );
    mgr->setFontFamily( mFontFamilyCombo->currentText() );
    mgr->setHexAreaWidth( mHexAreaWidthCombo->currentText().toInt());

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

    const QStringList sHexWidthList = { "", "8", "16", "32", "64", "80", "128" };

    mHexAreaWidthCombo->addItems(sHexWidthList);
    mHexAreaWidthCombo->setCurrentText( QString("%1").arg( mgr->getHexAreaWidth() ));


    if( manApplet->isLicense() )
    {
        state = mgr->getUseLogTab() ? Qt::Checked : Qt::Unchecked;
        mUseLogTabCheck->setCheckState(state);
    }
    else
    {
        mUseLogTabCheck->setEnabled(false);
        mUseDeviceMechCheck->setEnabled(false);
        mgr->setUseDeviceMech(false);
        mgr->setUseLogTab(false);
        mFileReadSizeGroup->setEnabled(false);
        mLogLevelGroup->setEnabled(false);
    }

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
    mFindMaxObjectsCountText->setText( QString( "%1").arg( mgr->getFindMaxObjectsCount() ) );

    QIntValidator *intVal = new QIntValidator( 0, 999999 );
    mFileReadSizeText->setValidator( intVal );
    mFileReadSizeText->setText( QString("%1").arg(mgr->getFileReadSize()));

    mUseDeviceMechCheck->setChecked( mgr->getUseDeviceMech() );
    mFontFamilyCombo->setCurrentText( mgr->getFontFamily() );

    mLangCombo->setCurrentIndex(I18NHelper::getInstance()->preferredLanguage());
    tabWidget->setCurrentIndex(0);
}
