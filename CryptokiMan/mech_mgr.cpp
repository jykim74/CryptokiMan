/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "mech_rec.h"
#include "mech_mgr.h"
#include "mainwindow.h"
#include "man_applet.h"
#include "cryptoki_api.h"
#include "js_pkcs11.h"

MechMgr::MechMgr()
{
    slot_id_ = -1;
    mech_list_.clear();
}

void MechMgr::clearList()
{
    mech_list_.clear();
}

void MechMgr::setSlotID( long slot_id )
{
    slot_id_ = slot_id;
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

int MechMgr::loadMechList()
{
    CK_MECHANISM_TYPE_PTR   pMechType = NULL;
    CK_ULONG ulMechCnt = 0;

    if( slot_id_ < 0 ) return -1;

    mech_list_.clear();

    int rv = manApplet->cryptokiAPI()->GetMechanismList( slot_id_, pMechType, &ulMechCnt );
    if( rv != CKR_OK )
    {
        manApplet->elog( QString("failed to get mechanism list [%1]").arg( rv ));
        return rv;
    }

    pMechType = (CK_MECHANISM_TYPE_PTR)JS_calloc( ulMechCnt, sizeof(CK_MECHANISM_TYPE));
    rv = manApplet->cryptokiAPI()->GetMechanismList( slot_id_, pMechType, &ulMechCnt );

    if( rv != CKR_OK )
    {
        manApplet->elog( QString("failed to get mechanism list2 [%1]").arg( rv ));
        return rv;
    }

    for(int i = 0; i < ulMechCnt; i++ )
    {
        CK_MECHANISM_INFO   stMechInfo;

        rv = manApplet->cryptokiAPI()->GetMechanismInfo( slot_id_, pMechType[i], &stMechInfo );
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

const QStringList MechMgr::getDeriveList()
{
    QStringList deriveList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_DERIVE )
            deriveList.append( rec.getIDName() );
    }

    return  deriveList;
}

const QStringList MechMgr::getWrapList( int type )
{
    QStringList wrapList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {

        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_WRAP )
        {
            QString strName = rec.getIDName();

            if( type == MECH_TYPE_SYM )
            {
                if( strName.contains( "RSA", Qt::CaseInsensitive) == false )
                    wrapList.append( strName );
            }
            else if( type == MECH_TYPE_ASYM )
            {
                if( strName.contains( "RSA", Qt::CaseInsensitive) == true )
                    wrapList.append( strName );
            }
            else
            {
                wrapList.append( strName );
            }
        }
    }

    return  wrapList;
}

const QStringList MechMgr::getUnwrapList( int type )
{
    QStringList unwrapList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_UNWRAP )
        {
            QString strName = rec.getIDName();

            if( type == MECH_TYPE_SYM )
            {
                if( strName.contains( "RSA", Qt::CaseInsensitive) == false )
                    unwrapList.append( strName );
            }
            else if( type == MECH_TYPE_ASYM )
            {
                if( strName.contains( "RSA", Qt::CaseInsensitive) == true )
                    unwrapList.append( strName );
            }
            else
            {
                unwrapList.append( strName );
            }
        }
    }

    return  unwrapList;
}

const QStringList MechMgr::getGenerateList()
{
    QStringList genList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_GENERATE )
            genList.append( rec.getIDName() );
    }

    return  genList;
}

const QStringList MechMgr::getGenerateKeyPairList()
{
    QStringList keyPairList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_GENERATE_KEY_PAIR )
            keyPairList.append( rec.getIDName() );
    }

    return  keyPairList;
}

const QStringList MechMgr::getSignList( int type )
{
    QStringList signList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_SIGN )
        {
            QString strName = rec.getIDName();

            if( type == MECH_TYPE_SYM )
            {
                if( strName.contains( "MAC", Qt::CaseInsensitive) == true )
                    signList.append( strName );
            }
            else if( type == MECH_TYPE_ASYM )
            {
                if( strName.contains( "MAC", Qt::CaseInsensitive) == false )
                    signList.append( strName );
            }
            else
            {
                signList.append( strName );
            }
        }
    }

    return signList;
}

const QStringList MechMgr::getVerifyList( int type )
{
    QStringList verifyList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_VERIFY )
        {
            QString strName = rec.getIDName();

            if( type == MECH_TYPE_SYM )
            {
                if( strName.contains( "MAC", Qt::CaseInsensitive) == true )
                    verifyList.append( strName );
            }
            else if( type == MECH_TYPE_ASYM )
            {
                if( strName.contains( "MAC", Qt::CaseInsensitive) == false )
                    verifyList.append( strName );
            }
            else
            {
                verifyList.append( strName );
            }
        }
    }

    return verifyList;
}

const QStringList MechMgr::getEncList( int type )
{
    QStringList encList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_ENCRYPT )
        {
            QString strName = rec.getIDName();

            if( type == MECH_TYPE_SYM )
            {
                if( strName.contains( "RSA", Qt::CaseInsensitive) == false )
                    encList.append( strName );
            }
            else if( type == MECH_TYPE_ASYM )
            {
                if( strName.contains( "RSA", Qt::CaseInsensitive) == true )
                    encList.append( strName );
            }
            else
            {
                encList.append( strName );
            }
        }
    }

    return encList;
}

const QStringList MechMgr::getDecList( int type )
{
    QStringList decList;

    for( int i = 0; i < mech_list_.size(); i++ )
    {
        MechRec rec = mech_list_.at(i);

        if( rec.getFlags() & CKF_DECRYPT )
        {
            QString strName = rec.getIDName();

            if( type == MECH_TYPE_SYM )
            {
                if( strName.contains( "RSA", Qt::CaseInsensitive) == false )
                    decList.append( strName );
            }
            else if( type == MECH_TYPE_ASYM )
            {
                if( strName.contains( "RSA", Qt::CaseInsensitive) == true )
                    decList.append( strName );
            }
            else
            {
                decList.append( strName );
            }
        }
    }

    return decList;
}
