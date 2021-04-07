#ifndef SLOT_INFO_H
#define SLOT_INFO_H

#include <QString>

class SlotInfo
{
private:
    QString     desc_;
    long        slot_id_;
    long        session_handle_;
    bool        login_;

public:
    SlotInfo();

    QString getDesc() { return desc_; };
    long getSlotID() { return slot_id_; };
    long getSessionHandle() { return session_handle_; };
    bool getLogin() { return login_; };

    void setDesc( const QString desc );
    void setSlotID( long slot_id );
    void setSessionHandle( long session_handle );
    void setLogin( bool login );
};

#endif // SLOT_INFO_H
