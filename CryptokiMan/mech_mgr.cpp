#include "mech_rec.h"
#include "mech_mgr.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "cryptoki_api.h"
#include "js_pkcs11.h"

MechMgr::MechMgr()
{
    mech_list_.clear();
}

void MechMgr::clearList()
{
    mech_list_.clear();
}

void MechMgr::add( const MechRec& mechRec )
{
    mech_list_.append( mechRec );
}

void MechMgr::add( int id, int min_size, int max_size, int flags )
{
    MechRec rec;
    rec.setID( id );
    rec.setMinSize( min_size );
    rec.setMaxSize( max_size );
    rec.setFlags( flags );

    mech_list_.append( rec );
}

int MechMgr::loadMechList( long slotid )
{
    CK_MECHANISM_TYPE_PTR   pMechType = NULL;
    CK_ULONG ulMechCnt = 0;

    int rv = manApplet->cryptokiAPI()->GetMechanismList( slotid, pMechType, &ulMechCnt );
    if( rv != CKR_OK )
    {
        manApplet->elog( QString("fail to get mechanism list: %1").arg( rv ));
        return rv;
    }

    pMechType = (CK_MECHANISM_TYPE_PTR)JS_calloc( ulMechCnt, sizeof(CK_MECHANISM_TYPE));
    rv = manApplet->cryptokiAPI()->GetMechanismList( slotid, pMechType, &ulMechCnt );

    if( rv != CKR_OK )
    {
        manApplet->elog( QString("fail to get mechanism list2: %1").arg( rv ));
        return rv;
    }

    for(int i = 0; i < ulMechCnt; i++ )
    {
        CK_MECHANISM_INFO   stMechInfo;

        rv = manApplet->cryptokiAPI()->GetMechanismInfo( slotid, pMechType[i], &stMechInfo );
        if( rv != CKR_OK ) continue;

        add( pMechType[i], stMechInfo.ulMinKeySize, stMechInfo.ulMaxKeySize, stMechInfo.flags );
    }

    if( pMechType ) JS_free( pMechType );
    return CKR_OK;
}

const QStringList MechMgr::getDigestList()
{
    QStringList digestList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_DIGEST )
            digestList.append( rec.getIDName() );
    }

    return  digestList;
}
