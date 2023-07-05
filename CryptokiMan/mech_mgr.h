#ifndef MECHMGR_H
#define MECHMGR_H

#include <QList>
#include <QStringList>

enum { MECH_TYPE_ALL, MECH_TYPE_SYM, MECH_TYPE_ASYM };

class MechRec;

class MechMgr
{
private:
    QList<MechRec> mech_list_;

public:
    MechMgr();
    void clearList();

    void setSlotID( long slot_id );
    void add( const MechRec& mechRec );
    void add( int id, int min_size, int max_size, int flags );

    int loadMechList();

    const QStringList getDigestList();
    const QStringList getDeriveList();
    const QStringList getWrapList( int type = MECH_TYPE_ALL );
    const QStringList getUnwrapList( int type = MECH_TYPE_ALL );
    const QStringList getGenerateList();
    const QStringList getGenerateKeyPairList();
    const QStringList getSignList( int type = MECH_TYPE_ALL );
    const QStringList getVerifyList( int type = MECH_TYPE_ALL );
    const QStringList getEncList( int type = MECH_TYPE_ALL );
    const QStringList getDecList( int type = MECH_TYPE_ALL );

private:
    long slot_id_;
};

#endif // MECHMGR_H
