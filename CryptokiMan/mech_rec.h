/*
 * Copyright (C) 2024 JayKim <jykim74@gmail.com>
 *
 * All rights reserved.
 */
#ifndef MECHREC_H
#define MECHREC_H

#include <QString>

class MechRec
{
private:
    int     id_;
    int     min_size_;
    int     max_size_;
    int     flags_;

    QString id_name_;

public:
    MechRec();

    int getID() { return id_; };
    const QString getIDName() { return id_name_; };
    int getMinSize() { return min_size_; };
    int getMaxSize() { return max_size_; };
    int getFlags() { return flags_; };

    void setID( int id );
    void setMinSize( int min_size );
    void setMaxSize( int max_size );
    void setFlags( int flags );
};

#endif // MECHREC_H
