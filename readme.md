# Proyecto ALBATROSS

Este proyecto consiste en comparar el rendimiento del protocolo ALBATROSS implementado con Grupos Cíclicos y con Curvas Elípticas. Para ello se ha simulado un entorno distribuido con una serie de nodos Flask que simulen ser los distintos participantes.

## Requisitos

- Python 3.12 o superior
- Dependencias que aparecen en el archivo `requirements.txt`

## Ejecución

Hay preparado un archivo `main.py` que se encarga de levantar tantos nodos como n participantes se hayan determinado y realizar la lógica del ledger,
o se puede implementar un script propio que genere los nodos para los participantes deseados (reciben como parámetros el número ordinal y un booleano para modo debug) y un nodo de ledger
 (recibe como parámetros el número n de participantes, el orden p del grupo cíclico y un booleano que define si se ejecuta con curvas elípticas o con grupos cíclicos)

**Importante**: si n es mayor que 40 fallará la ejecución

**Importante**: El orden del grupo cíclico es 2147483647, si se quiere usar uno más grande equivalente a la seguridad de la curva elíptica,
 sustituir en las líneas 68 y 69 de `main.py` los cálculos del generador y del subgrupo multiplicativo, pues si no nunca terminará

Ejemplo:

``` bash
py .\main.py --n 11 --ec True
```