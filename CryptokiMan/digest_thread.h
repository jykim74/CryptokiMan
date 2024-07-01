#ifndef DIGESTTHREAD_H
#define DIGESTTHREAD_H

#include <QThread>

class DigestThread : public QThread
{
    Q_OBJECT
public:
    DigestThread();
    ~DigestThread();

signals:
    void taskFinished();
    void taskUpdate( int nUpdate );

protected:
    void run() override;
};

#endif // DIGESTTHREAD_H
