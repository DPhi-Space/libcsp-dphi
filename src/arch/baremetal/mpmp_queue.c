/*============================================================================*
 *  mpmc_queue_freertos.c — implementation                                    *
 *============================================================================*/
#include "csp/arch/mpmc_queue.h"
#include <string.h>            /* memcpy */

/*──────────────────────────  Constructor  ────────────────────────────────*/
QueueHandle_t xQueueCreateStatic( UBaseType_t  uxQueueLength,
                                  UBaseType_t  uxItemSize,
                                  uint8_t    * pucQueueStorageBuffer,
                                  StaticQueue_t * pxStaticQueue )
{
    if ( ( uxQueueLength == 0U )            ||
         ( uxItemSize   == 0U )            ||
         ( pucQueueStorageBuffer == NULL ) ||
         ( pxStaticQueue        == NULL ) )
    {
        return ( QueueHandle_t ) 0;
    }

    uint16_t key = _mpmc_cs_enter();
    pxStaticQueue->pucBuffer  = pucQueueStorageBuffer;
    pxStaticQueue->uxLength   = uxQueueLength;
    pxStaticQueue->uxItemSize = uxItemSize;
    pxStaticQueue->head       = 0U;
    pxStaticQueue->tail       = 0U;
    pxStaticQueue->count      = 0U;
    _mpmc_cs_exit( key );

    return ( QueueHandle_t ) pxStaticQueue;
}

/*────────────────────────────  Send  ─────────────────────────────────────*/
BaseType_t xQueueSend( QueueHandle_t xQueue,
                       const void  * pvItemToQueue,
                       TickType_t    ignored/* xTicksToWait (ignored) */ )
{
    if ( ( xQueue == NULL ) || ( pvItemToQueue == NULL ) ) return pdFAIL;

    StaticQueue_t * q = ( StaticQueue_t * ) xQueue;
    uint16_t key = _mpmc_cs_enter();

    BaseType_t res;
    if ( q->count < q->uxLength )                     /* space available? */
    {
        memcpy( &q->pucBuffer[ q->head * q->uxItemSize ],
                pvItemToQueue,
                q->uxItemSize );

        if ( ++q->head == q->uxLength ) q->head = 0U;
        ++q->count;
        res = pdPASS;
    }
    else
    {
        res = pdFAIL;                                /* queue full        */
    }

    _mpmc_cs_exit( key );
    return res;
}

/*───────────────────────────  Receive  ───────────────────────────────────*/
BaseType_t xQueueReceive( QueueHandle_t xQueue,
                          void        * pvBuffer,
                          TickType_t    ignored/* xTicksToWait (ignored) */ )
{
    if ( ( xQueue == NULL ) || ( pvBuffer == NULL ) ) return pdFAIL;

    StaticQueue_t * q = ( StaticQueue_t * ) xQueue;
    uint16_t key = _mpmc_cs_enter();

    BaseType_t res;
    if ( q->count > 0U )                              /* queue non-empty?  */
    {
        memcpy( pvBuffer,
                &q->pucBuffer[ q->tail * q->uxItemSize ],
                q->uxItemSize );

        if ( ++q->tail == q->uxLength ) q->tail = 0U;
        --q->count;
        res = pdPASS;
    }
    else
    {
        res = pdFAIL;                                /* queue empty       */
    }

    _mpmc_cs_exit( key );
    return res;
}

/*───────────────────────  Messages waiting  ─────────────────────────────*/
UBaseType_t uxQueueMessagesWaiting( QueueHandle_t xQueue )
{
    if ( xQueue == NULL ) return 0U;
    StaticQueue_t * q = ( StaticQueue_t * ) xQueue;

    uint16_t key = _mpmc_cs_enter();
    UBaseType_t cnt = q->count;
    _mpmc_cs_exit( key );
    return cnt;
}

/* … existing #includes and functions … */

/*──────────────────────  Spaces available  ───────────────────────────────*/
UBaseType_t uxQueueSpacesAvailable( QueueHandle_t xQueue )
{
    if ( xQueue == NULL ) return 0U;

    StaticQueue_t * q = ( StaticQueue_t * ) xQueue;

    uint16_t key = _mpmc_cs_enter();                 /* keep it atomic       */
    UBaseType_t avail = q->uxLength - q->count;      /* free slots left      */
    _mpmc_cs_exit( key );

    return avail;
}

/* … existing functions … */

/*──────────────────────────  Queue reset  ────────────────────────────────*/
/*  Return pdPASS on success, pdFAIL if xQueue is NULL.  The routine is    */
/*  non-blocking and does not attempt to unblock tasks that might have     */
/*  been waiting (because this tiny port never blocks in the first place). */
BaseType_t xQueueReset( QueueHandle_t xQueue )
{
    if ( xQueue == NULL )
        return pdFAIL;

    StaticQueue_t * q = ( StaticQueue_t * ) xQueue;

    uint16_t key = _mpmc_cs_enter();    /* atomic section                  */
    q->head  = 0U;
    q->tail  = 0U;
    q->count = 0U;
    _mpmc_cs_exit( key );

    return pdPASS;
}
