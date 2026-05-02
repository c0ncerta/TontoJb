# Especificación Técnica de Parámetros y Límites (TontoJB)

| Variable | Valor Recomendado | Límite Máximo | Impacto si se Supera |
| :--- | :--- | :--- | :--- |
| `NUM_SDS` | 320 | **512** | Agotamiento de FDs (Cierre de app). |
| `NUM_SDS_ALT` | 40 | **128** | Memoria excesiva en sockets. |
| `NUM_RACES` | 400 | **1000** | Activación del Watchdog de Netflix por lag. |
| `NUM_GROOMS` | 512 | **1024** | Fragmentación excesiva (Kernel Panic). |
| `MAX_AIO_IDS` | 128 | **128** | Límite físico de Orbis para peticiones AIO. |
| `MAX_ROUNDS_TWIN`| 512 | **1024** | Lag en el Radar y potencial pérdida de estabilidad. |
| `auto_retry_count`| 15 | **25** | Tiempo de ejecución total excesivo. |
| `churn_socks` | 16 | **24** | Interferencia entre hilos en el Core 4. |
| `AIO_BUDGET` | 640 | **1024** | Saturación del Slab allocator. |

## Etiquetas de Memoria (Tags)

- **`LIVE_MARKER`** (`0x1337BEEF`): Firma de integridad.
- **`RTHDR_TAG`** (`0x13370000`): Base para identificación del spray.
- **`RTHDR_TAG_UAF`** (`0x1337F000`): ID único para el ganador del Stage 1.

## Constantes de Arquitectura (PS5 11.60)

- **`UCRED_SIZE`**: 360 bytes.
- **`KQ_FDP`**: Offset 0xA8.
- **`KQ_MAGIC_OFF8`**: 0x1430000.
- **`MAIN_CORE`**: Núcleo 4.
