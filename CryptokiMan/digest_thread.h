#ifndef DIGESTTHREAD_H
#define DIGESTTHREAD_H

#include <QThread>

class DigestThread : public QThread
{
    Q_OBJECT
public:
    DigestThread();
    ~DigestThread();
    void setSession( long uSession );
    void setSrcFile( const QString strSrcFile );

signals:
    void taskFinished();
    void taskUpdate( qint64 nUpdate );

protected:
    void run() override;
    long session_;
    QString src_file_;
};

#endif // DIGESTTHREAD_H
