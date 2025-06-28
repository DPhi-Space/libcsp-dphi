/*============================================================================*
 *  mpmc_queue_freertos.h — FreeRTOS-style static queue for MSP430FR5994     *
 *                                                                            *
 *  Copyright © 2025  Your-Project-Name-Here — MIT licence                    *
 *============================================================================*/
#ifndef MPMC_QUEUE_FREERTOS_H_
#define MPMC_QUEUE_FREERTOS_H_

#include <stdint.h>
#include <msp430.h>
#include "bsp.h"

#define portTICK_PERIOD_MS  ( ( TickType_t ) ( 1000UL / BSP_TICKS_PER_SEC ) )

#ifdef __cplusplus
extern "C" {
#endif

/*────────────────────  Minimal FreeRTOS portability types  ────────────────*/
#ifndef pdPASS                    /* allow coexistence with “real” FreeRTOS */
  typedef int32_t  BaseType_t;
  typedef uint32_t UBaseType_t;
  typedef uint32_t TickType_t;                 /* ignored in this tiny port  */

  #define pdPASS ( ( BaseType_t ) 1 )
  #define pdFAIL ( ( BaseType_t ) 0 )
	typedef int portBASE_TYPE;          /* or int32_t on a 32-bit core   */
#endif

/*────────────────────  Internal critical-section helpers  ─────────────────*/
static inline uint16_t _mpmc_cs_enter( void )
{
    uint16_t sr = __get_SR_register();
    __disable_interrupt();                 /*  CLR.GIE                       */
    return sr;
}
static inline void _mpmc_cs_exit( uint16_t saved_sr )
{
    if ( saved_sr & GIE ) __enable_interrupt();
}

/*──────────────────────────  Queue control block  ─────────────────────────*/
typedef struct
{
    uint8_t          * pucBuffer;   /* user-supplied byte array              */
    UBaseType_t        uxLength;    /* number of elements                    */
    UBaseType_t        uxItemSize;  /* bytes per element                     */
    volatile UBaseType_t head;      /* next write index                      */
    volatile UBaseType_t tail;      /* next read  index                      */
    volatile UBaseType_t count;     /* current item count                    */
} StaticQueue_t;

typedef StaticQueue_t * QueueHandle_t;

#define xQueueSendToBack xQueueSend
#define xQueueSendToBackFromISR(handle, value, task_woken) xQueueSend(handle, value, 0)
#define xQueueReceiveFromISR(handle, value, task_woken) xQueueReceive(handle, value, 0)
#define uxQueueMessagesWaitingFromISR uxQueueMessagesWaiting

/*────────────────────────────  Public API  ────────────────────────────────*/
QueueHandle_t xQueueCreateStatic( UBaseType_t  uxQueueLength,
                                  UBaseType_t  uxItemSize,
                                  uint8_t    * pucQueueStorageBuffer,
                                  StaticQueue_t * pxStaticQueue );

BaseType_t    xQueueSend        ( QueueHandle_t xQueue,
                                  const void  * pvItemToQueue,
                                  TickType_t    xTicksToWait );

BaseType_t    xQueueReceive     ( QueueHandle_t xQueue,
                                  void        * pvBuffer,
                                  TickType_t    xTicksToWait );

UBaseType_t   uxQueueMessagesWaiting( QueueHandle_t xQueue );
UBaseType_t uxQueueSpacesAvailable( QueueHandle_t xQueue );
BaseType_t xQueueReset( QueueHandle_t xQueue );

#ifdef __cplusplus
}
#endif
#endif /* MPMC_QUEUE_FREERTOS_H_ */
