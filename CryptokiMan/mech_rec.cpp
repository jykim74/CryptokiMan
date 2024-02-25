/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#include "mech_rec.h"
#include "js_pkcs11.h"

MechRec::MechRec()
{
    id_ = -1;
    min_size_ = -1;
    max_size_ = -1;
    flags_ = -1;
    id_name_ = "";
}

void MechRec::setID( int id )
{
    id_ = id;

    id_name_ = JS_PKCS11_GetCKMName( id );
}

void MechRec::setMinSize( int min_size )
{
    min_size_ = min_size;
}

void MechRec::setMaxSize( int max_size )
{
    max_size_ = max_size;
}

void MechRec::setFlags( int flags )
{
    flags_ = flags;
}
