#ifndef MECHMGR_H
#define MECHMGR_H

#include <QList>
#include <QStringList>

class MechRec;

class MechMgr
{
private:
    QList<MechRec> mech_list_;

public:
    MechMgr();
    void clearList();

    void add( const MechRec& mechRec );
    void add( int id, int min_size, int max_size, int flags );

    int loadMechList( long slotid );

    const QStringList getDigestList();
};

#endif // MECHMGR_H
