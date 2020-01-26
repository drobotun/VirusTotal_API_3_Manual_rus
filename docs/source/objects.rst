Объекты API
===========

Файлы (files)
-------------

Файлы являются одним из наиболее важных типов объектов в VirusTotal API. У нас есть огромный набор данных из более чем 2 миллиардов файлов, которые были проанализированы VirusTotal на протяжении многих лет. Объект ``file`` может быть получен либо путем загрузки нового файла в VirusTotal, либо путем поиска уже существующего хэша файла, либо другими способами при поиске в службах VT Enterprise services. В объекте ``file`` вы найдете некоторые релевантные базовые атрибуты о файле и его связи с VirusTotal:

- хэш-суммы файлов, такие как ``md5``, ``sha1`` и ``sha256``, которые однозначно идентифицируют файл;
- ``size`` - размер файла;
- ``first_submission_date`` - дата и время когда файл был впервые получен в VirusTotal (как временная метка UNIX);
- ``last_analysis_date`` - дата и время последнего анализа файла (как временная метка UNIX);
- ``last_modification_date`` - дата и время последнего изменения файла (как временная метка UNIX);
- ``times_submitted`` - число загрузок файла на сервер;
- ``last_analysis_results`` - результаты последнего анализа;
- ``names`` - имя файла ``meaningful_name``, которое мы считаем наиболее содержательным;
- ``downloadable`` - показывает возможность скачивания файла с сервера;
- ``unique_sources`` - указывает, из скольких различных источников был получен файл.

.. rubric:: JSON

::

    {
      "data": {
        "type": "file",
        "id": "<SHA256>",
        "links": {
          "self": "https://www.virustotal.com/api/v3/files/<SHA256>"
        },
        "attributes" : {
          "md5": "<string>",
          "sha1": "<string>",
          "sha256": "<string>",
          "size": <int>,
          "first_submission_date": "<unix_timestamp>",
          "last_submission_date": "<unix_timestamp>",
          "last_modification_date": "<unix_timestamp>",
          "times_submitted": <int>,
          "last_analysis_date": "<unix_timestamp>",
          "last_analysis_results": [ <objects> ],      
          "names": [ <strings> ],
          "meaningful_name": "<string>",
          "downloadable": <boolean>,
          "unique_sources": <int>,
          ...
        }
      } 
    }

В словаре атрибутов присутствует также поля с информацией, извлеченной из самого файла. Эта информация раскрыта в следующих ключах:

- ``type_description`` - описание типа файла, с коротким его представлением ``type_tag``, который можно использовать для поиска файлов этого типа;
- ``creation_date`` - извлекается, когда это возможно, из файла и указывает метку времени компиляции или сборки, может быть подделан создателями вредоносных программ;
- ``total_votes`` - общее количество голосов по результатам голосования пользователей VirusTotal Community. Поле ``reputation`` рассчитывается на основе голосов, полученных файлом, и репутации пользователей;
- ``vhash`` - значение т. н. нечеткого хэша, определяемого по алгоритму кластеризации, основанного на простом структурном хэше признаков, и который позволяет находить похожие файлы;
- ``tags`` - извлекаются из разных частей отчета и являются метками, которые помогают вам искать похожие образцы.

.. rubric:: JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "type_description": "<string>",
          "type_tag": "<string>",
          "creation_date": "<unix_timestamp>",
        
          "ssdeep": "<string>",
          "vhash": "<vhash>",
          "authentihash": "<string>",
      
          "reputation": <int>,
          "total_votes": { "harmless": <int>, "malicious": <int> },
          "tags": [ "<strings>" ]
        }
      }
    }

Кроме того, VirusTotal вместе с каждым антивирусным сканированием запускает набор утилит, позволяющих собирать дополнительную информацию о файле. Вся эта информация содержится в поле ``attributes`` вместе с остальными ранее описанными полями.

androguard
~~~~~~~~~~

Информация об Android файлах.

``androguard`` показывает информацию о файлах Android APK, DEX и XML, извлеченных с помощью утилиты Androguard.

- ``Activities`` - список активностей (activities) приложения;
- ``AndroguardVersion`` - версия используемой утилиты Androguard;
- ``AndroidApplication`` - тип файла Android в формате целого числа;
- ``AndroidApplicationError`` - логическое переменная со значением `False`;
- ``AndroidApplicationInfo`` - тип файла Android ("APK"," DEX","XML");
- ``AndroidVersionCode`` - код версии Android, считанный из манифеста;
- ``AndroidVersionName`` - имя версии Android, считанное из манифеста;
- ``Libraries`` - список библиотек, используемых приложением;
- ``Main Activity`` - название основной активности (activitie), прочитанное из манифеста;
- ``MinSdkVersion`` - минимальная поддерживаемая версия SDK;
- ``Package`` - имя пакета, считанное из манифеста;
- ``Permissions`` - словарь с разрешениями, используемыми в качестве ключа и списка с 3 элементами в качестве значения:

	- тип разрешения (например, ``normal``, ``dangerous``);
	- короткий дескриптор разрешения;
	- дескриптор разрешения;
	
- ``Providers`` - список провайдеров (providers), используемых приложением;
- ``Receivers`` - список получателей (receivers), используемых приложением;
- ``RiskIndicator`` - словарь с показателями риска ``APK`` (structure) и ``PERM`` (permissions):

	- ``APK`` - показывает используемые компоненты и их количество (например, ``"EXECUTABLE": 3``);
	- ``PERM`` - показывает типы разрешений и их количество (например, ``"DANGEROUS": 11``);
	
- ``Services`` - список служб (services), используемых приложением;
- ``StringsInformation`` - список примечательных строк, найденных в приложении;
- ``TargetSdkVersion`` - версия Android, на которой приложение было протестировано;
- ``VTAndroidInfo`` - версия Androguard, используемая сервисом VirusTotal;
- ``certificate`` - сведения о сертификате приложения в виде словаря с полями:

	- ``Issuer`` - словарь с отличительными (уникальными) именами и значениями. Типичными записями являются ``DN`` (отличительное (уникальное) имя), ``CN`` (общее имя), ``O`` (организация);
	- ``Subject`` - словарь с RDN (перечнем уникальных имен) эмитента сертификата;
	- ``serialnumber`` - серийный номер сертификата;
	- ``thumbprint`` - хэш сертификата в шестнадцатеричном виде;
	- ``validfrom`` - дата начала действия сертификата в `формате <http://strftime.org/>`_ "%H:%M %p %m/%d/%Y";
	- ``validto`` - срок действия сертификата, в формате "%H:%M %p %m/%d/%Y";
	
- ``intent-filters`` - фильтр предполагаемых действий приложения исходя из активностей (activities), получателей (receivers) и служб (services).

.. rubric:: Информация об APK файлах в виде JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "androguard": {
            "Activities": ["<strings>"],
            "AndroguardVersion": "<string>",
            "AndroidApplication": <int>,
            "AndroidApplicationError": <boolean>,
            "AndroidApplicationInfo": "<string>",
            "AndroidVersionCode": "<string>",
            "AndroidVersionName": "<string>",
            "Libraries": ["<strings>"],
            "Main Activity": "<string>",
            "MinSdkVersion": "<string>",
            "Package": "<string>",
            "Permissions": {"<string>": ["<strings>"], ... },
            "Providers": ["<strings>"],
            "Receivers": ["<strings>"],
            "RiskIndicator": {"APK": {"<string>": <int>, ... },
                              "PERM": {"<string>": <int>, ... }},
            "Services": ["<strings>"],
            "StringsInformation": ["<strings>"],
            "TargetSdkVersion": "<string>",
            "VTAndroidInfo": <float>,
            "certificate": {"Issuer": {"DN": "<string>", "O": "<string>", ... },
                            "Subject": {"DN": "<string>","O": "<string>", ... },
                            "serialnumber": "<string>",
                            "thumbprint": "<string>",
                            "validfrom": "<string:%H:%M %p %m/%d/%Y>",
                            "validto": "<string:%H:%M %p %m/%d/%Y>"},
            "intent-filters": {"Activities": {"<string>": {"action": ["<strings>"],
                                                           "category": ["<string>"]},
                                               ... },
                               "Receivers": {"<string>": {"action": ["<strings>"],
                                                          "category": ["<string>"]},
                                              ... },
                               "Services": {"<string>": {"action": ["<strings>"],
                                                         "category": ["<string>"]},
                                             ...}
          }
        }
      }
    }

asf_info
~~~~~~~~

Информация о Microsoft Advanced Streaming/Systems Format (ASF) файлах.

``asf_info`` показывает информацию о Microsoft ASF files (.asf, .wma, .wmv).

- ``content_encryption_object`` - информация о том, как зашифрован файл:

	- ``key_id`` - ID тиспользуемого ключа;
	- ``license_url`` - url-адрес лицензии;
	- ``protection_type`` - тип используемой защиты (например, "DRM");
	- ``secret_data`` - байты, содержащие секретные данные;
	
- ``extended_content_encryption_object`` - расширенная информация о том, как зашифрован файл:

	- ``CHECKSUM`` - контрольная сумма данных;
	- ``KID`` - ID тиспользуемого ключа;
	- ``EncodeType`` - тип кодирования;
	- ``LAINFO`` - информация о лицензионном соглашении;
	- ``DRMHeader`` - заголовок, используемый в DRM;
	
- ``script_command_objects`` - скрипты, используемые в файле:

	- ``action`` - действие, которое необходимо выполнить;
	- ``type`` - тип действия (например, `URL`, `FILENAME`, `EVENT`);
	- ``trigger_time`` - время активации скрипта.

.. rubric:: Информация об ASF файлах в виде JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "asf_info": {
            "content_encryption_object": {"key_id": "<string>",
                                          "license_url": "<string>",
                                          "protection_type": "<string>",
                                          "secret_data": "<string>"},
            "extended_content_encryption_object": {"CHECKSUM": "<string>",
                                                   "DRMHeader": "<string>",
                                                   "EncodeType": "<string>",
                                                   "KID": "<string>",
                                                   "LAINFO":"<string>"},
            "script_command_objects": [{"action": "<string>",
                                        "trigger_time": <int>,
                                        "type":"URL"}, ... ]}
        }
      }
    }

authentihash
~~~~~~~~~~~~

Хэш для проверки PE-файлов.

``authentihash`` - это хэш sha256, используемый корпорацией Microsoft для проверки того, что соответствующие разделы образа PE-файла не были изменены.

.. rubric:: JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "authentihash": "<string>",
        }
      }
    }

bundle_info
~~~~~~~~~~~

Информация о сжатых файлах.

``bundle_info`` предоставляет информацию о сжатых файлах (ZIP, TAR, GZIP и т. д.).

- ``beginning`` - распакованный заголовок файла для некоторых форматов файлов (GZIP, ZLIB);
- ``extensions`` - расширения файлов и их количество внутри пакета;
- ``file_types`` - типы файлов и их количество внутри пакета;
- ``highest_datetime`` - самая последняя дата в содержащихся файлах, в `формате <http://strftime.org/>`_ "%H:%M %p %m/%d/%Y";
- ``lowest_datetime`` - самая старая дата в содержащихся файлах, в формате "%H:%M %p %m/%d/%Y";
- ``num_children`` - сколько файлов и каталогов находится внутри пакета;
- ``tags`` - интересные замечания о содержании (например, `"contains-pe"`);
- ``type`` - тип пакета (например, "ZIP");
- ``uncompressed_size`` - несжатый размер содержимого внутри сжатого файла;
- ``vhash`` - хэш подобия (нечеткий хэш) для этого типа файлов.

.. rubric:: Информация о сжатых файлах в виде JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "bundle_info": {
            "beginning": "<string>",
            "extensions": {"<string>": <int>, ... },
            "file_types": {"<string>": <int>, ... },
            "highest_datetime": "<string:%Y-%m-%d %H:%M:%S>",
            "lowest_datetime": "<string:%Y-%m-%d %H:%M:%S>",
            "num_children": <int>,
            "tags": ["<strings>"],
            "type": "<string>",
            "uncompressed_size": <int>,
            "vhash": "<string>"
          }
        }
      }
    }

class_info
~~~~~~~~~~

Информация о классах Java в байткод-файлах.

``class_info`` предоставляет информацию о Java байткод-файлах.

- ``constants`` - константы, используемые в классе;
- ``extends`` -  класс, от которого наследован данный класс;
- ``implements`` - интерфейсы реализованные в классе;
- ``methods`` - методы, принадлежащие к классу;
- ``name`` - имя класса;
- ``platform`` - платформа в виде строки, полученной из старшего и младшего номера версии;
- ``provides`` - представленные классы, поля и методы;
- ``requires`` - обязательные классы, поля и методы.

.. rubric:: Информация о Java классе в виде JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "class_info": {
            "constants": ["<strings>"],
            "extends": "<string>",
            "implements": ["<strings>"],
            "methods": ["<strings>"],
            "name": "<string>",
            "platform": "<string>",
            "provides": ["<strings>"],
            "requires": ["<strings>"]
          }
        }
      }
    }

deb_info
~~~~~~~~

Информация о Debian пакетах.

``deb_info`` - предоставляет информацию о `Debian пакетах <https://wiki.debian.org/Packaging>`_.

- ``changelog`` - информация об изменениях в версии пакета:

	- ``Author`` - имя автора;
	- ``Date`` дата в `формате <http://strftime.org/>`_ "%a, %d %b %Y %H:%M%S %z";
	- ``Debian revision`` - ревизия;
	- ``Debian version`` - версия;
	- ``Distributions`` - тип распространения;
	- ``Full version`` - полная версия системы;
	- ``Package`` - тип пакета;
	- ``Urgency`` - уровень срочности изменений;
	- ``Version history`` - история версий;
	
- ``control_metadata`` - общие (неизменные) поля пакета:

	- ``Maintainer`` - идентификатор того, кто осуществляет поддержку пакета;
	- ``Description`` - дескриптор пакета;
	- ``Package`` - имя пакета;
	- ``Depends`` - зависимости пакета;
	- ``Version`` - версия пакета;
	- ``Architecture`` - архитектура для запуска этого пакета (например, ``"i386"``);
	
- ``control_scripts`` - сценарии для запуска в операциях управления пакетами:

	- ``postinst`` - скрипт, выполняемый после инсталляции;
	- ``postrm`` - скрипт, выполняемый после удаления пакета;
	
- ``structural_metadata``:

	- ``contained_files`` - количество файлов в пакете;
	- ``contained_items`` - количество пунктов в пакете;
	- ``max_date`` - дата самого старого файла в формате "%Y-%m-%d %H:%M%S";
	- ``min_date`` - самая последняя дата файла в формате "%Y-%m-%d %H:%M%S".

.. rubric:: Информация о Debian пакете в виде JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "deb_info": {
            "changelog": {"Author": "<string>",
                          "Date": "<string:%a, %d %b %Y %H:%M%S %z>",
                          "Debian revision": "<string>",
                          "Debian version": "<string>",
                          "Distributions": "<string>",
                          "Full version": "<string>",
                          "Package": "<string>",
                          "Urgency": "<string>",
                          "Version history": "<string>"},
            "control_metadata": {"<string>": "<string>", ... },
            "control_scripts": {"postinst": "<string>",
                                "postrm": "<string>"},
            "structural_metadata": {"contained_files": <int>,
                                    "contained_items": <int>,
                                    "max_date": "<string:%Y-%m-%d %H:%M%S>",
                                    "min_date": "<string:%Y-%m-%d %H:%M%S>"}
          }
        }
      }
    }

dmg_info
~~~~~~~~

Информация о монтируемых образах дисков macOS.

``dmg_info`` сообщает данные о структуре `файлов Apple.dmg <https://en.wikipedia.org/wiki/Apple_Disk_Image>`_). Большая часть данных поступает из метаданных внутренних файлов, которые могут содержаться в некоторых файлах, а в других - нет.

- ``blkx`` - список блоков в образе. Каждая запись содержит:

	- ``attributes`` - в формате шестнадцатеричного числа;
	- ``name`` - имя блока;
	
- ``data_fork_length`` - размер данных форка;
- ``data_fork_offset`` - смещение данных форка;
- ``dmg_version`` - версия DMG-файла;
- ``hfs`` - информация об HFS-элементах. В зависимости от конкретного случая могут присутствовать различные поля:

	- ``info_plist`` - содержимое списка свойств (plist) данного блока;
	- ``main_executable`` - основной исполняемый файл этого блока:
	
		- ``id`` - идентификатор;
		- ``path`` - путь в пакете;
		- ``sha256`` - хэш содержимого;
		- ``size`` - размер файла в байтах;
		
	- ``num_files`` - количество файлов;
	- ``unreadable_files`` - количество нечитаемых файлов;
	
- ``plist`` - содержит сведения о конфигурации приложения, такие как идентификатор пакета, номер версии и отображаемое имя;
- ``plist_keys`` - ключи от записи ``plist``;
- ``running_data_fork_offset`` - смещение начала используемых данных форка (обычно 0);
- ``resourcefork_keys`` - ключи, найденные в ресурсах форка;
- ``rsrc_fork_length`` - длина ресурсов форка;
- ``rsrc_fork_offset`` - смещение ресурсов форка;
- ``xml_lenght`` - размер списка свойств в DMG;
- ``xml_offset`` - смещение списка свойств в DMG.

.. rubric:: Apple .dmg-файл

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "dmg_info": {
            "blkx": [{"attributes": "<string>", "name": "<string>"}, ... ],
            "data_fork_length": <int>,
            "data_fork_offset": <int>,
            "dmg_version": <int>,
            "hfs": {"info_plist": {"<string>": <value>, ... },
                    "main_executable": {"id": <int>,
                                        "path": "<string>",
                                        "sha256": "<string>",
                                        "size": <int>},
                    "<string>": <value>,
                    ... },
            "plst": [{"attributes": "<string>", "name": "<string>"}],
            "plst_keys": ["<strings>"],
            "running_data_fork_offset": <int>,
            "resourcefork_keys": ["<strings>"],
            "rsrc_fork_length": <int>,
            "rsrc_fork_offset": <int>,
            "xml_length": <int>,
            "xml_offset": <int>
          }
        }
      }
    }

dot_net_guids
~~~~~~~~~~~~~

Идентификаторы для сборок Microsoft .NET.

- ``dot_net_guids`` - список `идентификаторов для сборок Microsoft .NET <https://www.virusbulletin.com/virusbulletin/2015/06/using-net-guids-help-hunt-malware/>`_;
- ``mvid`` - ModuleVersionID, генерируемый во время сборки, в результате чего для каждой сборки создается новый идентификатор GUID;
- ``typelib_id`` - TypeLibID (если имеется), созданный Visual Studio при создании нового проекта по умолчанию.

.. rubric:: ID сборки Microsoft .NET в виде JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "dot_net_guids": {
            "mvid": "<string>",
            "typelib_id": "<string>"
          }
        }
      }
    }

elf_info
~~~~~~~~

Информация о Unix ELF-файлах.

``elf_info`` возвращает информацию о `Unix ELF file format <https://en.wikipedia.org/wiki/Executable_and_Linkable_Format>`_.

- ``exports`` - список экспортируемых элементов. Каждый элемент содержит имя и тип.
- ``header`` - некоторые описательные метаданные о файле:

	- ``type`` - тип файла (например ``"EXEC"`` (исполняемый файл);
	- ``hdr_version`` - версия заголовка;
	- ``num_prog_headers`` - количество записей в заголовке программы;
	- ``os_abi`` - тип бинарного интерфейса приложения (например ``"UNIX-Linux"``);
	- ``obj_version`` - ``0x1`` для оригинальных ELF-файлов;
	- ``machine`` - платформа (например ``"Advanced Micro Devices X86-64"``);
	- ``entrypoint`` - точка входа;
	- ``num_section_headers`` - число секций в заголовке;
	- ``abi_version`` - версия бинарного интерфейса приложения;
	- ``data`` - выравнивание данных в памяти (например ``"little endian"``);
	- ``class`` - класс файла (например ``"ELF32"``);
	
- ``imports`` - список импортируемых элементов. Каждый элемент содержит имя и тип;
- ``sections`` - секции ELF-файла:

	- ``name`` - имя секции;
	- ``address`` - виртуальный адрес секции;
	- ``flags`` - атрибуты секции;
	- ``offset`` - смещение секции;
	- ``type`` - тип секции;
	- ``size`` - размер секции в байтах;
	
- ``segments`` - они же заголовки программ. каждый элемент содержит тип сегмента и список ресурсов, задействованных в этом сегменте;
- ``shared_libraries`` - список общих библиотек, используемых этим исполняемым файлом.

.. rubric:: Формат ELF-файла

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "elf_info": {
            "exports": [["<string>", "<string>"], ... ],
            "header": {"type": "<string>",
                       "hdr_version": "<string>",
                       "num_prog_headers": <int>,
                       "os_abi": "<string>",
                       "obj_version": "<string>",
                       "machine": "<string>",
                       "entrypoint": <int>,
                       "num_section_headers" <int>,
                       "abi_version": 0,
                       "data": "<string>",
                       "class": "<string>"},
            "imports": [["<string>", "<string>"], ... ],
            "sections": [{"name": "<string>",
                          "address": <int>,
                          "flags": "<string>",
                          "offset": <int>,
                          "type": "<string>",
                          "size": <int>}, ... ],
            "segments": [["<string>", ["<strings>"]], ... ],
            "shared_libraries": ["<strings>"]
          }
        }
      }
    }

exiftool
~~~~~~~~

Информация о метаданных EXIF из файлов.

``exiftool`` это утилита для извлечения метаданных EXIF из файлов различных форматов. Представляемые метаданные могут различаться в зависимости от типа файла, и, учитывая природу метаданных EXIF, соcтав отображаемых полей может различаться.

Например:

- поля для Microsoft Windows PE-файлов:

::

    CharacterSet, CodeSize, CompanyName, EntryPoint, FileDescription, FileFlagsMask,
    FileOS, FileSize, FileSubtype, FileType, FileTypeExtension, FileVersion,
    FileVersionNumber, ImageVersion, InitializedDataSize, InternalName, LanguageCode,
    LegalCopyright, LinkerVersion, MIMEType, MachineType, OSVersion, ObjectFileType,
    OriginalFileName,, PEType, ProductName, ProductVersion, ProductVersionNumber,
    Subsystem, SubsystemVersion, TimeStamp, UninitializedDataSize

- поля для JPEG-файлов:

::

    Aperture, ApertureValue, BitsPerSample, BrightnessValue, CircleOfConfusion,
    ColorComponents, ColorSpace, Compression, CreateDate, DateTimeOriginal,
    DeviceType, EncodingProcess, ExifByteOrder, ExifImageHeight, ExifImageWidth,
    ExifVersion, ExposureCompensation, ExposureMode, ExposureProgram, ExposureTime,
    FNumber, FOV, FaceDetect, FileType, FileTypeExtension, Flash, FlashpixVersion,
    FocalLength, FocalLength35efl, FocalLengthIn35mmFormat, HyperfocalDistance,
    ISO, ImageHeight, ImageSize, ImageUniqueID, ImageWidth, InteropIndex,
    InteropVersion, LightValue, MIMEType, Make, MakerNoteVersion, MaxApertureValue,
    Megapixels, MeteringMode, Model, ModifyDate, Orientation, RawDataByteOrder,
    RawDataCFAPattern, ResolutionUnit, ScaleFactor35efl, SceneCaptureType,
    ShutterSpeed, ShutterSpeedValue, Software, SubSecCreateDate,
    SubSecDateTimeOriginal, SubSecModifyDate, SubSecTime, SubSecTimeDigitized,
    SubSecTimeOriginal, ThumbnailImage, ThumbnailLength, ThumbnailOffset,
    TimeStamp, WhiteBalance, XResolution, YCbCrPositioning, YCbCrSubSampling,
    YResolution

- поля для PDF_файла:

::

    CreateDate, Creator, CreatorTool, DocumentID, FileType, FileTypeExtension,
    Linearized, MIMEType, ModifyDate, PDFVersion, PageCount, Producer, XMPToolkit

.. rubric:: JSON

::

    {
      "data": {
		   ...
        "attributes" : {
          ...
          "exiftool": {
             "<string>": "<string>", ... 
          }
        }
      }
    }

image_code_injections
~~~~~~~~~~~~~~~~~~~~~

Инъекция кода в файл изображения.

``image_code_injections`` возвращает содержимое внедренного кода в файлах изображений.

.. rubric:: JSON

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "image_code_injections": "<string>"
        }
      }
    }

ipa_info
~~~~~~~~

Информация об iOS App Store Package файле.


isoimage_info
~~~~~~~~~~~~~

Информация о файлах ISO-образов.

``isoimage_info`` - возвращает информацию о структуре ISO-файлов.

- ``application_id`` - приложение, использованное для создания файла;
- ``created`` - время создания файла в `формате <http://strftime.org/>`_ "%Y-%m-%d %H:%M:%S";
- ``effective`` - фактическая дата тома в формате "%Y-%m-%d %H:%M:%S";
- ``expires`` - дата истечения срока действия тома в формате "%Y-%m-%d %H:%M:%S";
- ``file_structure_version`` - версия файловой структуры;
- ``max_date`` - самая "свежая" дата, содержащаяся в файле в формате "%Y-%m-%d %H:%M:%S";
- ``min_date`` - самая старая содержащаяся дата файла в формате "%Y-%m-%d %H:%M:%S";
- ``modified`` - дата последней модификации в формате "%Y-%m-%d %H:%M:%S";
- ``num_files`` - количество файлов содержащихся ISO-образе;
- ``system_id`` - имя системы, которая может работать с начальными секторами (например ``"Win32"``);
- ``total_size`` - размер всех разделов в этом логическом томе;
- ``type_code`` - код типа формата (например ``"CD001"``);
- ``volume_id`` - идентификатор тома;
- ``volume_set_id`` - идентификатор объединенного тома.

.. rubric:: Файл ISO-образа

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "isoimage_info": {
            "application_id": "<string>",
            "created": "<string:%Y-%m-%d %H:%M:%S>",
            "effective": "<string:%Y-%m-%d %H:%M:%S>",
            "expires": "<string:%Y-%m-%d %H:%M:%S>",
            "file_structure_version": <int>,
            "max_date": "<string:%Y-%m-%d %H:%M:%S>",
            "min_date": "<string:%Y-%m-%d %H:%M:%S>",
            "modified": "<string:%Y-%m-%d %H:%M:%S>",
            "num_files": <int>,
            "system_id": "<string>",
            "total_size": <int>,
            "type_code": "<string>",
            "volume_id": "<string>",
            "volume_set_id": "<string>"
          }
        }
      }
    }

jar_info
~~~~~~~~

Информация о файлах Java Archive.

``jar_info`` возвращает информацию о Java jar-файлах.

- ``filenames`` - имена содержащихся файлов;
- ``files_by_type`` - типы и количество типов файлов, содержащихся в jar-файле;
- ``manifest`` - содержимое манифеста Jar;
- ``max_date`` - самая старая содержащаяся дата файла в `формате <http://strftime.org/>`_"%Y-%m-%d %H:%M:%S";
- ``max_depth`` - максимальная глубина каталога jar-файла;
- ``min_date`` - самая "свежая" дата, содержащаяся в файле в формате "%Y-%m-%d %H:%M:%S";
- ``packages`` - предполагаемые пакеты, используемые в пакете .class-файлов;
- ``strings`` - примечательные строки, найденные в пакете .class-файлов;
- ``total_dirs`` - количество каталогов в пакете;
- ``total_files`` - количество файлов в пакете.

.. rubric:: Java .jar-файлы

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "jar_info": {
            "filenames": ["<strings>"],
            "files_by_type": {"<string>": <int>, ... },
            "manifest": "<string>",
            "max_date": "<string:%Y-%m-%d %H:%M:%S>",
            "max_depth": <int>,
            "min_date": "<string:%Y-%m-%d %H:%M:%S>",
            "packages": ["<strings>"],
            "strings": ["<strings>"],
            "total_dirs": <int>,
            "total_files": <int>
          }
        }
      }
    }

macho_info
~~~~~~~~~~

Информация о файлах Apple MachO.

``macho_info`` возвращает информацию о файлах `формата Apple MachO <https://en.wikipedia.org/wiki/Mach-O>`_. Это список, содержащий элементы для каждого приложения:

- ``libs`` - библиотек, используемые в файле;
- ``headers`` - некоторые описательные метаданные о файле:
	
	- ``cpu_type`` - основной тип процессора (например ``i386``);
	- ``cpu_subtype`` - подтип процессора (например ``I386_ALL``);
	- ``magic`` - "магический" идентификатор приложения;
	- ``size_cmds`` - размер команд;
	- ``num_cmds`` - число команд;
	- ``flags`` флаги файлов (например ``DYLDLINK``, ``NOUNDEFS``);
	- ``file_type`` - тип файла (например ``dynamically bound shared library``);
		
- ``commands`` - список команд загрузки. Каждая запись отображается как значение ключа ``type``;
- ``segments`` - список сегментов файла:
	
	- ``name`` - имя сегмента;
	- ``fileoff`` - физический адрес сегмента;
	- ``vm size`` - размер виртуального адреса;
	- ``vmaddr`` - виртуальный адрес;
	- ``filesize`` - размер сегмента;
	- ``sections`` - секции сегмента:
		
		- ``type`` - тип секции;
		- ``flags`` - флаги секции (например ``S_8BYTE_LITERALS``);
		- ``name`` - имя секции;
			
	- ``vhash`` - vhash файла;
	- ``tags`` - общие замечания о файле (например ``64 bits``).
		
.. rubric:: Формат файла Apple MachO

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "macho_info": [
            {"libs": ["<strings>"],
             "headers": {"cpu_subtype": "<string>",
                         "magic": "<string>",
                         "size_cmds": <int>,
                         "file_type": "<string>",
                         "num_cmds": <int>,
                         "flags": ["<strings>"],
                         "cpu_type": "<string>"},
             "commands": [{"type": "<string>"}, ... ],
             "segments": [{"name": "<string>",
                           "fileoff": "<string>",
                           "vmsize": "<string>",
                           "filesize": "<string>",
                           "vmaddr": "<string>"}, ... ],
             "sections": [{"type": "<string>",
                           "flags": ["<strings>"],
                           "name": "<string>"}, ... ],
             "vhash": "<string>",
             "tags": ["<strings>"]} ...
          ]
        }
      }
    }

magic
~~~~~

Идентификация файлов по "магическому числу".

``magic`` дает предположение о типе файла, основываясь на популярном инструменте синтаксического анализа из UNIX (команда ``file``).

.. rubric:: Предполагаемый тип файла

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "magic": "<string>",
        }
      }
    }

office_info
~~~~~~~~~~~

Информация о структуре файлов Microsoft Office.


openxml_info
~~~~~~~~~~~~

Информация об Microsoft OpenXML файлах.


packers
~~~~~~~

Информация об упаковщике, используемом в файле.

``packers`` - определtybt упаковщиков PE-файлов, используемых в Windows с помощью нескольких утилит и антивирусных средств.

- ключи - это названия утилит, значения - это идентифицированные упаковщики.

.. rubric:: PEiD идентификатор упаковщика

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "packers": {"<string>": "<string>", ... }
        }
      }
    }


pdf_info
~~~~~~~~

Информация об Adobe PDF файлах.

``pdf_info`` возвращает информацию о структуре `файлов PDF <https://en.wikipedia.org/wiki/PDF>`_:

- ``acroform`` - содержание Acroforms;
- ``automation`` - автоматическое действие, выполняемое при просмотре документа;
- ``embedded_file`` - содержимое встроенного файла;
- ``encrypted`` - документ имеет DRM или нуждается в пароле для чтения;
- ``flash`` - содержит встроенный Flash;
- ``header`` - заголовок документа (например ``%PDF-1.7``);
- ``javascript`` - документ содержит JavaScript;
- ``jbig2_compression`` - документ сжат с применением JBIG2;
- ``js`` - документ содержит JavaScript;
- ``num_endobj`` - количество завершений объекта;
- ``num_endstream`` - количество завершений потока;
- ``num_launch_actions`` - количество запускаемых действий;
- ``num_obj`` - количество объектов;
- ``num_object_streams`` - количество потоков объектов;
- ``num_pages`` - количество страниц;
- ``num_stream`` - количество потоков;
- ``open action`` - автоматическое действие, выполняемое при просмотре документа;
- ``startxref`` - эта запись присутствует в документе;
- ``suspicious_colors`` - устанавливается, если количество цветов выражается более чем 3 байтами;
- ``trailer`` - содержит раздел трейлера;
- ``xref`` - таблица перекрестных ссылок.

.. rubric:: Структура Acrobat PDF файлов

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "pdf_info": {
             "acroform": <int>,
             "autoaction": <int>,
             "embedded_file": "<string>",
             "encrypted": <int>,
             "flash": <int>,
             "header": "<string>",
             "javascript": <int>,
             "jbig2_compression": <int>,
             "js": <int>,
             "num_endobj": <int>,
             "num_endsctream": <int>,
             "num_launch_actions": <int>,
             "num_obj": <int>,
             "num_object_streams": <int>,
             "num_pages": <int>,
             "num_stream": <int>,
             "openaction": <int>,
             "startxref": <int>,
             "suspicious_colors": "<string>",
             "trailer": <int>,
             "xref": <int>
          }
        }
      }

pe_info
~~~~~~~

Информация о файлах формата Microsoft Windows Portable Executable.


rombios_info
~~~~~~~~~~~~

Информация о BIOS, EFI, UEFI и связанных с ними архивах.


rtf_info
~~~~~~~~

Информация о файлах формата Microsoft Rich Text.


signature_info
~~~~~~~~~~~~~~

Информация о подписи PE-файлов.


ssdeep
~~~~~~

CTPH хэш содержимого файла.

`ssdeep` - программа для вычисления `контекстно-зависимого кусочного хэша <https://ssdeep-project.github.io/ssdeep/index.html>`_. Также называемый нечеткими хэшем, он позволяет идентифицировать похожие файлы.

.. rubric:: ssdeep

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "ssdeep": "<string>"
        }
      }
    }

swf_info
~~~~~~~~

Информация о Adobe Shockwave Flash файлах.

``swf_info`` возвращает информацию о файлах `Shockwave Flash/Small Web Format <https://en.wikipedia.org/wiki/SWF>`_:

- ``compression`` - тип используемого сжатия (наптимер ``zlib``);
- ``duration`` - длина медиа-контента в секундах;
- ``file_attributes``-  особые атрибуты (например ``ActionScript3``, ``UseGPU``);
- ``flash_packages`` - список  используемых Flash пакетов;
- ``frame_count``- количество фреймов;
- ``frame_size`` - размер фреймов;
- ``metadata`` - содержимое метаданных файла;
- ``num_swf_tags`` - количество тэгов SWF;
- ``num_unrecognized_tags``: количество нераспознанных тегов;
- ``suspicious_strings`` - список найденных подозрительных строк;
- ``suspicious_urls`` - список найденных подозрительных URL;
- ``tags`` - примечательные замечания о файле (например ``get-url``, ``ext-interface``);
- ``version`` - версия SWF.

.. rubric:: SWF файл

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "swf_info": {
            "compression": "<string>",
            "duration": <float>,
            "file_attributes": ["<strings>"],
            "flash_packages": ["<strings>"],
            "frame_count": <int>,
            "frame_size": "<string>",
            "metadata": "<string>",
            "num_swf_tags": <int>,
            "num_unrecognized_tags": <int>,
            "suspicious_strings": ["<strings>"],
            "suspicious_urls": ["<strings>"],
            "tags": ["<strings>"],
            "version": <int>
          }
        }
      }
    }

trid
~~~~

Тип файла идентифицированный с помощью утилиты `TrID <http://mark0.net/soft-trid-e.html>`_.

``trid`` - утилита, предназначенная для идентификации типов файлов по их бинарным сигнатурам. Может дать несколько результатов, упорядоченных от более высокой до более низкой вероятности идентификации формата файла (в процентах).

.. rubric:: TrID

::

    {
      "data": {
		    ...
        "attributes" : {
          ...
          "trid": [
            {"file_type": "<string>", "probability": <float>}, ... 
          ]
        }
      }
    }

Поведение файлов (file behaviour)
---------------------------------

Отчеты о поведении файлов.

Отчеты о поведении файлов получаются либо с помощью функции GET /files/{id}/behavior, либо с помощью анализа поведения в песочнице . Они суммируют наблюдаемое поведение во время выполнения или открытия файла. Обратите внимание, что некоторые из этих действий могут быть инициированы дочерними элементами рассматриваемого файла.

Объект ``file_behaviour`` содержит следующие атрибуты:

DnsLookup
~~~~~~~~~

DNS-запросы.

- ``hostname`` *<string>* - имя хоста DNS-запроса;
- ``resolved_ips`` *<string array>* - все разрешенные IP-адреса могут быть пустыми на NX домене.

DroppedFile
~~~~~~~~~~~

Сброшенные файлы - это файлы, специально созданные и записанные во время анализа поведения. Это может быть результатом загрузки содержимого из интернета и записи его в файл, распаковки файла, сброса некоторого содержимого в файл и т. д.

- ``path`` *<string>* - полный путь к файлу, включая имя файла;
- ``sha256`` *<string>* - SHA-256 хэш файла.

BehaviourTag
~~~~~~~~~~~~

Поведение в Sandbox было помечено сложной операцией:

- ``DETECT_DEBUG_ENVIRONMENT``
- ``DIRECT_CPU_CLOCK_ACCESS``
- ``LONG_SLEEPS``
- ``SELF_DELETE`` - файл удаляется сам по себе при выполнении.
- ``HOSTS_MODIFIER`` - файл local hosts изменен.
- ``INSTALLS_BROWSER_EXTENSION`` - устанавливает BHO, расширение Chrome и т. д.
- ``PASSWORD_DIALOG`` - отображается какая-то подсказка для ввода пароля.
- ``SUDO`` - повышает привилегии до администратора.
- ``PERSISTENCE`` - использует механизмы устойчивости, чтобы пережить перезагрузку.
- ``SENDS_SMS``
- ``CHECKS_GPS``
- ``FTP_COMMUNICATION``
- ``SSH_COMMUNICATION``
- ``TELNET_COMMUNICATION``
- ``SMTP_COMMUNICATION``
- ``MYSQL_COMMUNICAION``
- ``IRC_COMMUNICATION``
- ``SUSPICIOUS_DNS`` - возможен DGA (алгоритм генерации домена).
- ``SUSPICIOUS_UDP`` - большое количество различных UDP-соединений, это часто помогает выявить P2P.
- ``BIG_UPSTREAM`` - большой исходящий сетевой трафик.
- ``TUNNELING`` - наблюдается туннелирование сети, например, VPN.
- ``CRYPTO`` - использует API, связанные с криптографией.
- ``TELEPHONY`` - использует API, связанные с телефонией.
- ``RUNTIME_MODULES`` - динамически загружает библиотеки DLL или дополнительные компоненты.
- ``REFLECTION`` - выполняет отображение вызовов.

FileCopy
~~~~~~~~

Объект, описывающий копирование или перемещение файла:

- ``source`` *<string>* - полный путь к исходному файлу.
- ``destination`` *<string>* - полный путь к файлу назначения.

HttpConversation
~~~~~~~~~~~~~~~~

HTTP-вызовы.

- ``RequestMethod`` - один из:

	- ``GET``
	- ``HEAD``
	- ``POST``
	- ``PUT``
	- ``DELETE``
	- ``TRACE``
	- ``OPTIONS``
	- ``CONNECT``
	- ``PATCH``
	
- ``url`` - полное имя хоста и путь к указанному URL-адресу.
- ``request_headers`` ключи и значения:

	- ``key`` - например *Content-Type*;
	- ``value`` - например *image/jpeg*;
	
- ``response_headers`` - ключи и значения заголовков ответов.
- ``response_status_code`` - код состояния ответа, например ``200``.
- ``response_body_filetype``
- ``response_body_first_ten_bytes``

IpTraffic
~~~~~~~~~

IP-трафик:

- ``destination_ip`` *<string>* - IP-адрес.
- ``destination_port`` *<integer>* - номер порта.
- ``transport_layer_protocol`` -  один из:

	- ``ICMP``
	- ``IGMP``
	- ``TCP``
	- ``UDP``
	- ``ESP``
	- ``AH``
	- ``L2TP``
	- ``SCTP``

PermissionCheck
~~~~~~~~~~~~~~~

Записывает запрос, чтобы узнать, имеет ли данный компонент/пакет/процесс/служба определенное разрешение.

- ``permission`` *<string>* -  например: ``android.permission.INTERNET``.
- ``owner`` *<string>* - имя приложения, которому было предоставлено проверяемое разрешение.


Process
~~~~~~~

- ``process_id`` *<string>* - ID процесса.
- ``name`` *<string>* - имя процесса.
- ``time_offset`` *<integer>* - начало наблюдения. Секунды с момента начала исполнения.
- ``children`` *<Process array>* -  массив этого объекта ``Process``. Позволяет построить дерево процессов.

Sms
~~~

Отправлено SMS сообщение.

- ``destination`` *<string>* -  номер телефона, на который отправляется SMS.
- ``body`` *<string>* - текст сообщения.


VerdictTag
~~~~~~~~~~

Вердикты для пометки образца поведения в песочнице:

- ``CLEAN`` - чистый, занесенный в белый список или незамеченный.
- ``MALWARE`` - должно быть определено как вредоносное ПО
- ``GREYWARE`` - PUA, PUP (возможно, нежелательная программа).
- ``RANSOM`` - вымогатель или криптор.
- ``PHISHING`` - пытается обмануть пользователя, чтобы получить его учетные данные.
- ``BANKER`` - банковский троян.
- ``ADWARE`` - отображает нежелательную рекламу.
- ``EXPLOIT`` - содержит или запускает эксплойт.
- ``EVADER`` - содержит логику, позволяющую уклониться от анализа.
- ``RAT`` - троян для удаленного доступа, может прослушивать входящие соединения.
- ``TROJAN`` - троян или бот.
- ``SPREADER`` распространяется на USB, других накопителях, по сети и т. д.


Домены (domains)
----------------


communicating_files
~~~~~~~~~~~~~~~~~~~


communicating_files
~~~~~~~~~~~~~~~~~~~


downloaded_files
~~~~~~~~~~~~~~~~


graphs
~~~~~~


referrer_files
~~~~~~~~~~~~~~


resolutions
~~~~~~~~~~~


siblings
~~~~~~~~


IP-адреса (IP addresses)
------------------------


URL (URLs)
----------

Представления (submissions)
---------------------------


Скриншоты (screenshots)
-----------------------


Голоса (votes)
--------------