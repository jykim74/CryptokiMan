#include "slot_info.h"

SlotInfo::SlotInfo()
{
    desc_ = "";
    slot_id_ = -1;
    session_handle_ = -1;
    login_ = false;
}

void SlotInfo::setDesc(const QString desc)
{
    desc_ = desc;
}

void SlotInfo::setSlotID(long slot_id)
{
    slot_id_ = slot_id;
}

void SlotInfo::setSessionHandle(long session_handle)
{
    session_handle_ = session_handle;
}

void SlotInfo::setLogin(bool login)
{
    login_ = login;
}
