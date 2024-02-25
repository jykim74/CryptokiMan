/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MAN_TRAY_ICON_H
#define MAN_TRAY_ICON_H

#include <QObject>
#include <QSystemTrayIcon>

class ManTrayIcon : public QSystemTrayIcon
{
public:
    ManTrayIcon();
};

#endif // MAN_TRAY_ICON_H
