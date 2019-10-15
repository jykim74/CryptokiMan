#ifndef TEMP_ARRAY_H
#define TEMP_ARRAY_H

#ifndef _TempArray_H_
#define _TempArray_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

template <class Type> class CTempArray
{
private:
    enum {
        nDefaultSize = 24,
    };
    Type**		m_array;
    int			m_count;
    int			m_size;

public:
    CTempArray();
    CTempArray(int size);
    CTempArray(const CTempArray<Type>& tempArray);
    ~CTempArray();

    void reset();
    void add(Type rec);
    void add(Type *rec);
    Type* get(int index) const;
    int count() const { return m_count; };
    int sort(int(*diffFunc)(Type& A, Type& B)); /* Bubble Sort */
    int swap(int idxA, int idxB);

private:
    void _clear();
    void _clear(Type** array, int count);
    void _deleteAll();
};

template <class Type>
CTempArray<Type>::CTempArray()
{
    m_size = nDefaultSize;

    m_array = new Type*[m_size];
    m_count = 0;

    _clear();
}

template <class Type>
inline CTempArray<Type>::CTempArray(int size)
{
    m_size = size;

    m_array = new Type*[m_size];
    m_count = 0;

    _clear();
};

template <class Type>
inline CTempArray<Type>::CTempArray(const CTempArray<Type>& tempArray)
{
    m_size = tempArray.m_size;
    m_array = new Type*[m_size];
    _clear();

    m_count = tempArray.m_count;

    for (int i = 0; i < m_count; i++)
        m_array[i] = new Type(*tempArray.m_array[i]);
};


template <class Type>
inline CTempArray<Type>::~CTempArray()
{
    _deleteAll();

    if (m_array) delete[] m_array;
};

template <class Type>
inline void CTempArray<Type>::reset()
{
    _deleteAll();
    m_count = 0;
};

template <class Type>
inline void CTempArray<Type>::add(Type rec)
{
    if (m_count >= m_size)
    {
        Type** tmpArray = new Type*[m_size * 2];
        _clear(tmpArray, m_size * 2);

        for (int i = 0; i < m_size; i++)
            tmpArray[i] = m_array[i];

        delete[] m_array;
        m_array = tmpArray;
        m_size *= 2;
    }

    m_array[m_count] = new Type(rec);
    m_count++;
};

template <class Type>
inline void CTempArray<Type>::add(Type *rec)
{
    if (m_count >= m_size)
    {
        Type** tmpArray = new Type*[m_size * 2];
        _clear(tmpArray, m_size * 2);

        for (int i = 0; i < m_size; i++)
            tmpArray[i] = m_array[i];

        delete[] m_array;
        m_array = tmpArray;
        m_size *= 2;
    }

    m_array[m_count] = rec;
    m_count++;
};

template <class Type>
inline Type* CTempArray<Type>::get(int index) const
{
    if (index < 0 || index >= m_count)
        return NULL;

    return m_array[index];
};


/* Bubble Sort */
template <class Type>
inline int CTempArray<Type>::sort(int(*diffFunc)(Type& A, Type& B))
{
    for (int i = 0; i < m_count - 1; i++)
    {
        for (int j = 0; j < m_count - i - 1; j++)
        {
            if (diffFunc(*m_array[j], *m_array[j + 1]) > 0)
                swap(j, j + 1);
        }
    }

    return 0;
}

template <class Type>
inline int CTempArray<Type>::swap(int idxA, int idxB)
{
    if (idxA < 0 || idxA >= m_count) return -1;
    if (idxB < 0 || idxB >= m_count) return -2;

    Type* tmp;

    tmp = m_array[idxB];
    m_array[idxB] = m_array[idxA];
    m_array[idxA] = tmp;

    return 0;
}

template <class Type>
inline void CTempArray<Type>::_clear()
{
    for (int i = 0; i < m_size; i++)
        m_array[i] = NULL;
};

template <class Type>
inline void CTempArray<Type>::_clear(Type** array, int count)
{
    for (int i = 0; i < count; i++)
        array[i] = NULL;
}

template <class Type>
inline void CTempArray<Type>::_deleteAll()
{
    if (m_array == NULL) return;

    for (int i = 0; i < m_size; i++)
    {
        if (m_array[i] != NULL)
        {
            delete m_array[i];
            m_array[i] = NULL;
        }
    }
};

#endif


#endif // TEMP_ARRAY_H
