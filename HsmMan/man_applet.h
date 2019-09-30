#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>


class ManApplet : public QObject
{
    Q_OBJECT

public:
    ManApplet( QObject *parent = nullptr );
};

#endif // MAN_APPLET_H
