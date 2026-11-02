# lsass_cng

Дамп LSASS через загрузчик CNG key storage provider. На диске обычный полный minidump `lsass.exe`. Хендл lsass не открывается. `SeDebugPrivilege` на lsass не нужен. `AddSecurityPackage` нет. Служба и пакет не регистрируются. Образ попадает в процесс lsass один раз. Каждый следующий запуск дёргает только уже загруженный код. Ребут не нужен.

## Сборка

Любой mingw-w64: кросс с Linux или macOS, либо сборка на Windows.

```sh
./build.sh              # bin/lsass_cng.exe и bin/cng_dump.dll (x64)

# или руками:
x86_64-w64-mingw32-gcc -shared -O2 -s src/cng_shim.c -o bin/cng_dump.dll -lkernel32
x86_64-w64-mingw32-gcc -municode -O2 -s src/lsass_cng.c -o bin/lsass_cng.exe \
    -lkernel32 -ladvapi32 -lsecur32
```

Заголовки SDK не нужны, хватает mingw. В рантайме `kernel32`, `advapi32`, `secur32`, `msvcrt`. `dbghelp.dll` резолвится уже внутри lsass. `build.sh` проверяет, что шим экспортирует ровно `GetKeyStorageInterface`. Это единственный экспорт, который ищет загрузчик ncrypt.

## Запуск

Консоль с system. `cng_dump.dll` лежит рядом с exe.

```text
lsass_cng.exe                          дамп -> lsass.dmp рядом с exe
lsass_cng.exe C:\out\lsass.dmp         свой путь
lsass_cng.exe --fresh                  новое имя образа (обновление шима
                                       на живом lsass)
```

Коды выхода:

* `0` успех
* `1` кривые аргументы
* `2` RunAsPPL
* `3` путь, dll или копирование
* `4` регистрация провайдера
* `5` триггер не прошёл (SYSTEM, SeTcb или logon API)
* `6` после триггера образ не замапился
* `7` таймаут payload, 120 с.
* `8` дамп не записался (маркер ERR от payload)

## Ограничения

* Только x64.

## Дисклеймер

Только авторизованный пентест, редтим и исследование. Дамп lsass раскрывает учётки. Без разрешения на чужой системе это незаконно. За чужое использование автор ответственности не несёт.
