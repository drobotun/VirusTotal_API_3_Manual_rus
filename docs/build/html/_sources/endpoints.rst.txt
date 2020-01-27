Основные функции VirusTotal API
===============================

Files (Функции для работы с файлами)
------------------------------------

Файлы являются одним из наиболее важных типов объектов в API VirusTotal. У нас есть огромный набор данных из более чем 2 миллиардов файлов, которые были проанализированы VirusTotal на протяжении многих лет. В этом разделе описываются функции API для анализа новых файлов и получения информации о любом файле в нашем наборе данных.

POST /files
~~~~~~~~~~~

Загрузка и анализ файла.

|POST| ``https://www.virustotal.com/api/v3/files``

.. rubric:: cURL

::

    curl --request POST \
      --url https://www.virustotal.com/api/v3/files \
      --header 'x-apikey: <your API key>' \
      --form file=@/path/to/file

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    with open("<путь к файлу>", "rb") as file:
        files = {"file": ("<путь к файлу>", file)}
        response = requests.post(api_url, headers=headers, files=files)

.. rubric:: Параметры запроса

- **file** - файл для сканирования.

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Файлы могут быть загружены в VirusTotal путем отправки POST-запросов, закодированных как ``multipart/form-data`` в конечную точку ``https://www.virustotal.com/api/v3/files``. Каждый POST-запрос должен иметь поле с именем ``file``, содержащее файл для анализа. Общий размер полезной нагрузки не может превышать 32 МБ. Для загрузки больших файлов см. `GET /files/upload_url`_.

Результат, возвращаемый этой функцией, является дескриптором объекта для нового анализа. Идентификатор, содержащийся в дескрипторе, можно использовать с функцией GET /analyses/{id} для получения информации о результатах анализа этого файла.

Для анализа файла, который ранее уже был загружен в VirusTotal, можно использовать `POST /files/{id}/analyse`_.

.. rubric:: Пример ответа

::

    {
      "data": {
        "type": "analysis",
        "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
      }
    }

GET /files/upload_url
~~~~~~~~~~~~~~~~~~~~~

Получение URL для загрузки файла больше 32 МБ.

|GET| ``https://www.virustotal.com/api/v3/files/upload_url``

.. rubric:: cURL

::

   curl --request GET \
     --url https://www.virustotal.com/api/v3/files/upload_url \
     --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/upload_url"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    response = requests.get(api_url, headers=headers)

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Для загрузки файлов размером менее 32 МБ вы можете просто использовать функцию `POST /files`_, но для файлов большего размера необъодимо сначала получить специальный URL загрузки, а затем отправить POST-запрос  на этот URL. Этот POST-запрос должен иметь тот же формат, что и для функции `POST /files`_. Каждый полученный URL можно использовать только один раз.

.. note:: Файлы размером более 200 МБ. Обратите внимание, что файлы размером более 200 МБ, как правило, представляют собой пакеты какого-либо вида (сжатые файлы, ISO-образы и т. д.) в этих случаях имеет смысл загрузить внутренние файлы отдельно по нескольким причинам:

- Движки некоторых антивирусов, как правило, имеют проблемы с производительностью при сканировании больших файлов (из-за больших тайм-аутов, некоторые из них могут даже не сканировать их);
- Движки некоторых антивирусов не могут проверять определенные типы файлов, в то время как они смогут проверить внутренние файлы, если они будут отправлены;
- При сканировании большого пакета вы теряете контекст, в котором конкретный внутренний файл вызывает обнаружение.

=======

.. rubric:: Пример ответа

::

    {
      "data": "http://www.virustotal.com/_ah/upload/AMmfu6b-_DXUeFe36Sb3b0F4B8mH9Nb-CHbRoUNVOPwG/"
    }


GET /files/{id}
~~~~~~~~~~~~~~~

Получение информации о файле.

|GET| ``https://www.virustotal.com/api/v3/files/{id}``

.. rubric:: cURL

::

    curl --request GET \
      --url https://www.virustotal.com/api/v3/files/{id} \
      --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    response = requests.get(api_url, headers=headers)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

.. rubric:: Пример ответа

::

    {    
      "type": "file",
      "id": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
      "links": {
        "self": "https://www.virustotal.com/api/v3/files/8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85"
      },
      "data": {
        "attributes": {
          "first_seen_itw_date": 1075654056,
          "first_submission_date": 1170892383,
          "last_analysis_date": 1502355193,
          "last_analysis_results": {
            "AVG": {
              "category": "undetected",
              "engine_name": "AVG",
              "engine_update": "20170810",
              "engine_version": "8.0.1489.320",
              "method": "blacklist",
              "result": null
            }
              ...
          },
          "last_analysis_stats": {
            "harmless": 0,
            "malicious": 0,
            "suspicious": 0,
            "timeout": 0,
            "type-unsupported": 8,
            "undetected": 59
          },
          "last_submission_date": 1502355193,
          "magic": "data",
          "md5": "76cdb2bad9582d23c1f6f4d868218d6c",
          "names": [
            "zipnew.dat",
            "327916-1502345099.zip",
            "ac3plug.zip",
            "IMG_6937.zip",
            "DOC952.zip",
            "20170801486960.zip"
          ],
          "nsrl_info": {
            "filenames": [
              "WINDOWS DIALUP.ZIP",
              "kemsetup.ZIP",
              "Data_Linux.zip",
              "2003.zip",
              "_6A271FB199E041FC82F4D282E68B01D6"
            ],
            "products": [
              "Master Hacker Internet Terrorism (Core Publishing Inc.)",
              "Read Rabbits Math Ages 6-9 (Smart Saver)",
              "Neverwinter Nights Gold (Atari)",
              "Limited Edition Print Workshop 2004 (ValuSoft)",
              "Crysis (Electronic Arts Inc.)"
            ]
          },
          "reputation": -889,
          "sha1": "b04f3ee8f5e43fa3b162981b50bb72fe1acabb33",
          "sha256": "8739c76e681f900923b900c9df0ef75cf421d39cabb54650c4b9ad19b6a76d85",
          "size": 22,
          "ssdeep": "3:pjt/l:Nt",
          "tags": [
            "software-collection",
            "nsrl",
            "attachment",
            "trusted",
            "via-tor"
          ],
          "times_submitted": 26471,
          "total_votes": {
            "harmless": 639,
            "malicious": 958
          },
          "trid": [
            {
              "file_type": "ZIP compressed archive (empty)",
              "probability": 100
            }
          ],
          "trusted_verdict": {
            "filename": "lprn_spotlightstory_015.zip",
            "link": "https://dl.google.com/dl/spotlight/test/lprn_spotlightstory/9/lprn_spotlightstory_015.zip",
            "organization": "Google",
            "verdict": "goodware"
          },
          "type_description": "unknown",
          }
        }
      }
    }

POST /files/{id}/analyse
~~~~~~~~~~~~~~~~~~~~~~~~

Повторный анализ файла в VirusTotal/
.. warning:: Эта функция API может привести к отказу в обслуживании инфраструктуры сканирования в случае неправильного использования. Пожалуйста, свяжитесь с нами, если вы собираетесь сканировать более 50 тысяч файлов в день.

|POST| ``https://www.virustotal.com/api/v3/files/{id}/analyse``

.. rubric:: cURL

::

    curl --request POST \
      --url https://www.virustotal.com/api/v3/files/{id}/analyse \
      --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}/analyse"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    response = requests.post(api_url, headers=headers)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Файлы, которые уже были загружены в VirusTotal, можно повторно проанализировать, не загружая их снова, используя эту функцию. Ответом является дескриптор объекта для нового анализа, как и в функции `POST /files`_. Идентификатор, содержащийся в дескрипторе, можно использовать с функцией GET /analyses/{id} для получения информации о результатах анализа.

.. rubric:: Пример ответа

::

    {
      "data": {
        "type": "analysis",
        "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
      }
    }

GET /files/{id}/comments
~~~~~~~~~~~~~~~~~~~~~~~~

Получение комментариев для файла

|GET| ``https://www.virustotal.com/api/v3/files/{id}/comments``

.. rubric:: cURL

::

    curl --request GET \
      --url https://www.virustotal.com/api/v3/files/{id}/comments \
      --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}/comments"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    query = {"limit": "<limit)>", "cursor": "<cursor>"}
    response = requests.get(api_url, headers=headers, params=query)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **limit** - максимальное число комментариев в ответе (int_32, необязательный параметр);
- **cursor** - курсор продолжения (string, необязательный параметр).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

POST /files/{id}/comments
~~~~~~~~~~~~~~~~~~~~~~~~~

Добавление комментария для файла.

|POST| ``https://www.virustotal.com/api/v3/files/{id}/comments``

.. rubric:: cURL

::

    curl --request POST \
      --url https://www.virustotal.com/api/v3/files/{id}/comments \
      --header 'x-apikey: <your API key>' \
      --data '{"data": {"type": "comment", "attributes": {"text": "Lorem ipsum dolor sit ..."}}}'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}/comments"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    comments = {"data": {"type": "comment", "attributes": {"text": "Lorem ipsum dolor sit ..."}}}
    response = requests.post(api_url, headers=headers, json=comments)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **data** - комментарий (json).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

С помощью этой функции вы можете опубликовать комментарий для данного файла. Тело POST-запроса должно быть JSON-представлением комментария. Обратите внимание, что вам не нужно указывать идентификатор объекта, так как он автоматически генерируется для новых комментариев.

Любое слово, начинающееся с ``#`` в тексте вашего комментария, будет считаться тегом и добавляться в атрибут тега комментария.

.. rubric:: Пример запроса

::

    {
      "data": {
        "type": "comment",
        "attributes": {
    	    "text": "Lorem #ipsum dolor sit ..."
        }
      }
    }

.. rubric:: Пример ответа

::

    {
      "data": {
        "type": "comment",
        "id": "<comment's ID>",
        "links": {
          "self": "https://www.virustotal.com/api/v3/comments/<comment's ID>"
        },
        "attributes": {
          "date": 1521725475,
          "tags": ["ipsum"],
          "html": "Lorem #ipsum dolor sit ...",
          "text": "Lorem #ipsum dolor sit ...",
          "votes": {
            "abuse": 0,
            "negative": 0,
            "positive": 0
          }
        }
      }
    }

GET /files/{id}/votes
~~~~~~~~~~~~~~~~~~~~~

Получение результатов голосования для файла

|GET| ``https://www.virustotal.com/api/v3/files/id/votes``

.. rubric:: cURL

::

    curl --request GET \
      --url https://www.virustotal.com/api/v3/files/{id}/votes \
      --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}/comments"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    query = {"limit": "<limit)>", "cursor": "<cursor>"}
    response = requests.get(api_url, headers=headers, params=query)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **limit** - максимальное число комментариев в ответе (int_32, необязательный параметр);
- **cursor** - курсор продолжения (string, необязательный параметр).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

POST /files/{id}/votes
~~~~~~~~~~~~~~~~~~~~~~

Добавление голоса для файла.

|POST| ``https://www.virustotal.com/api/v3/files/{id}/comments``

.. rubric:: cURL

::

    curl --request POST \
      --url https://www.virustotal.com/api/v3/files/{id}/votes \
      --header 'x-apikey: <your API key>' \
      --data '{"data": {"type": "vote", "attributes": {"verdict": "malicious"}}}''

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}/votes"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    votes = {"data": {"type": "vote", "attributes": {"verdict": "malicious"}}}
    response = requests.post(api_url, headers=headers, json=votes)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **data** - голос (json).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

С помощью этой функции вы можете опубликовать свой голос за данный файл. Тело для запроса POST должно быть JSON-представлением объекта голосования. Обратите внимание, однако, что вам не нужно указывать идентификатор объекта, так как они автоматически генерируются для новых голосов.

Атрибут ``verdict`` должен быть либо ``harmless``, либо ``malicious``.

.. rubric:: Пример ответа

::

    {
      "data": {
        "type": "vote",
        "attributes": {
    	    "verdict": "harmless"
        }
      }
    }

GET /files/{id}/download_url
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Получение URL для загрузки файла.

.. note:: Требуются особые привилегии. Эта функция доступна только для пользователей со специальными привилегиями.

|GET| ``https://www.virustotal.com/api/v3/files/id/download_url``

.. rubric:: cURL

::

    curl --request GET \
      --url https://www.virustotal.com/api/v3/files/{id}/download_url \
     --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}/download_url"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    response = requests.get(api_url, headers=headers)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Эта функция возвращает подписанный URL, с которого можно загрузить указанный файл. Получение URL считается загрузкой файла в квоте, даже если вы на самом деле не загружаете файл. URL можно использовать для загрузки файла несколько раз, не потребляя никакой квоты. Срок действия URL истекает через 1 час.

.. rubric:: Пример ответа

::

    {
      "data": "https://vtsamples.commondatastorage.googleapis.com/275a..fd0f?GoogleAccessId=758681729565-rc7fcckv235v1@developer.gserviceaccount.com&Expires=1524733537&Signature=GRs9WLy...oHA%3D"
    }

GET /files/{id}/download
~~~~~~~~~~~~~~~~~~~~~~~~

Загрузка файла.

.. note:: Требуются особые привилегии. Эта функция доступна только для пользователей со специальными привилегиями.

|GET| ``https://www.virustotal.com/api/v3/files/id/download``


.. rubric:: cURL

::

    curl --request GET \
      --url https://www.virustotal.com/api/v3/files/{id}/download \
      --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}/download"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    response = requests.get(api_url, headers=headers)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Эта функция похожа на `GET /files/{id}/download_url`_, но она перенаправляет вас на URL загрузки файла. URL загрузки, на который вы перенаправлены, может быть использован повторно столько раз, сколько вы хотите в течение 1 часа. После этого срока действие URL истекает и он больше не может быть использован.

GET /files/{id}/{relationship}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Получение объектов, связанных с файлом.

|GET| ``https://www.virustotal.com/api/v3/files/{id}/{relationship}``

.. rubric:: cURL

::

    curl --request GET \
      --url https://www.virustotal.com/api/v3/files/{id}/{relationship} \
      --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/files/{id}/{relationship}"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    query = {"limit": "<limit)>", "cursor": "<cursor>"}
    response = requests.get(api_url, headers=headers)

.. rubric:: Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **relationship** - наименование отношения (см. таблицу ниже);
- **limit** - максимальное число комментариев в ответе (int_32, необязательный параметр);
- **cursor** - курсор продолжения (string, необязательный параметр).

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Объекты типа ``file`` имеют ряд отношений с другими файлами и объектами. Как уже упоминалось в разделе "Отношения", эти связанные объекты можно получить, отправив GET-запросы на URL, соответствующий нужному отношению.

Некоторые отношения доступны только тем пользователям, которые имеют доступ к VirusTotal Intelligence.

.. rubric:: Отношения, поддерживаемые объектами файла:

.. table::

    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |Отношения               | Описание                                                      | Доступность                              |
    +========================+===============================================================+==========================================+
    |``analyses``            | Объект ``analyses`` для файла                                 | Только для пользователей **Intelligence**|
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``behaviours``          | Отчеты о поведении для файла.                                 | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``bundled_files``       | Файлы, собранные в одном файле.                               | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``carbonblack_children``| Файлы, полученные из файла Carbon Black                       | Только для пользователей **Intelligence**|
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``carbonblack_parents`` | Файлы Carbon Black, из которых был получен файл               | Только для пользователей **Intelligence**|
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``comments``            | Комментарии к файлу                                           | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``compressed_parents``  | Сжатые файлы, содержащие этот файл                            | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``contacted_domains``   | Домены, с которыми связан файл                                | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``contacted_ips``       | IP-адреса, с которыми связан файл                             | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``contacted_urls``      | URL, с которыми связан файл                                   | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``email_parents``       | Файлы электронной почты, содержащие этот файл                 | Только для пользователей **Intelligence**|
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``embedded_domains``    | Имена доменов, содержащиеся в файле                           | Только для пользователей **Intelligence**|
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``embedded_ips``        | IP-адреса, содержащиеся в файле                               | Только для пользователей **Intelligence**|
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``execution_parents``   | Файлы, которые запустили файл                                 | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``graphs``              | Графики, включающие файл                                      | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``itw_urls``            | URL "in the wild", откуда был загружен файл                   | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``overlay_parents``     | Файлы, содержащие файл в виде оверлея                         | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``pcap_parents``        | Файлы PCAP, содержащие этот файл                              | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``pe_resource_parents`` | PE-файлы, содержащие файл в качестве ресурса                  | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``similar_files``       | Файлы, похожие на данный файл                                 | Только для пользователей **Intelligence**|
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``submissions``         | Представления файла                                           | Только для пользователей **Intelligence**|
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``screenshots``         | Скриншоты, связанные с песочницей, в которой выполнялся файл  | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+
    |``votes``               | Результаты голосования для файла                              | Все пользователи                         |
    +------------------------+---------------------------------------------------------------+------------------------------------------+

GET /file_behaviours/{sandbox_id}/pcap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

|GET| ``https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/pcap``

.. rubric:: cURL

::

    curl --request GET \
      --url https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/pcap \
      --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/file_behaviours/{sandbox_id}/pcap"
    headers = {"x-apikey" : "<ключ доступа к API>"}
    response = requests.get(api_url, headers=headers)

.. rubric:: Параметры запроса

- **sandbox_id** - идентификатор, полученный из функции `GET /files/{id}/{relationship}`_, с ``параметром relationship`` равным ``behaviours``.

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

URLs (Функции для работы с URL-адресами)
----------------------------------------

VirusTotal анализирует не только файлы, но и URL-адреса. В этом разделе описаны функции API для анализа URL-адресов и получения информации о них.

Идентификатор URL-адреса
~~~~~~~~~~~~~~~~~~~~~~~~

Всякий раз, когда мы говорим об идентификаторе URL-адреса в этой документации, мы имеем в виду последовательность символов, которые однозначно идентифицируют конкретный URL. Эти идентификаторы могут принимать две формы:

- SHA-256 хэш от строки канонического URL-адреса;
- Строка, полученная в результате кодирования URL-адреса в base64 (без заполнения символами ``"="``).

Все идентификаторы URL-адресов, возвращаемые API VirusTotal, находятся в первой форме, и если у вас есть один из этих идентификаторов, вы можете использовать его в последующих вызовах API, которым требуется идентификатор URL-адреса. Однако создание таких идентификаторов самостоятельно может быть затруднено из-за алгоритма канонизации, который должен быть применен к URL-адресу перед вычислением SHA-256 хэша. Канонизация гарантирует, что два URL-адреса, отличающиеся только незначительными аспектами, например некоторыми экранированными символами, имеют один и тот же идентификатор. По этой причине мы предлагаем возможность идентификации URL-адреса путем кодирования его в base64 и использования результирующей строки в качестве идентификатора. В таких случаях URL-адрес не нужно канонизировать, это делается на стороне сервера VirusTotal.

Обратите внимание, что мы используем неупакованную кодировку base64, как определено в `разделе 3.2 RFC 4648 <https://tools.ietf.org/html/rfc4648#section-3.2>`_, что означает, что полученные идентификаторы URL-адресов не должны быть дополнены символами ``"="``, как это обычно происходит с данными, закодированными в base64.

Вот один из примеров того, как сгенерировать идентификатор URL-адреса:

.. code-block:: python

    import base64
      ...
    url_id = base64.urlsafe_b64encode("<строка с url-адресом>").strip("=")

POST /urls
~~~~~~~~~~

Анализ URL-адреса.

|POST| ``https://www.virustotal.com/api/v3/urls``

.. rubric:: cURL

::

    curl --request POST \
      --url https://www.virustotal.com/api/v3/urls \
      --header 'x-apikey: <your API key>' \
      --form url='<url>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/urls"
	headers = {"x-apikey" : "<ключ доступа к API>"}
	data = {'url': url}
    response = requests.post(api_url, headers=headers, data=data)

.. rubric:: Параметры запроса

- **url** - URL-адрес, который должен быть проанализирован.

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

URL-адреса могут быть отправлены в VirusTotal путем отправки POST-запросов. Каждый POST-запрос должен иметь поле с именем ``url``, содержащие URL-адрес, который должен быть проанализирован.

Результатом, возвращаемым этой функцией, является дескриптор объекта для нового анализа. Идентификатор, содержащийся в дескрипторе, можно использовать с конечной точкой GET /analyses/{id} для получения информации о результатах анализа.

Для анализа URL-адреса, ранее отправленного в VirusTotal, можно использовать POST /urls/{id}/analyse.

- ``id`` - идентификатор для последующего использования с другими вызовами;
- ``type`` - значение ``analysis``.

.. rubric:: Структура ответа

::

    {
      "data": {"id": "<string>", "type": "analysis"}
    }

POST /urls/{id}
~~~~~~~~~~~~~~~

Получение информации об URL-адресе.

|GET| ``https://www.virustotal.com/api/v3/urls/{id}``

.. rubric:: cURL

::

    curl --request GET \
      --url https://www.virustotal.com/api/v3/urls/{id} \
      --header 'x-apikey: <your API key>'

.. rubric:: Python

.. code-block:: python

    import requests
        ...
    api_url = "https://www.virustotal.com/api/v3/urls{id}"
	headers = {"x-apikey" : "<ключ доступа к API>"}
	response = requests.get(api_url, headers=headers)
	
.. rubric:: Параметры запроса

- **id** - идентификатор URL-адреса.

.. rubric:: Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

.. hint:: Дополнительные сведения о создании допустимого идентификатора URL-адреса см. в разделе "`Идентификатор URL-адреса`_".

.. rubric:: Структура ответа

::

    {
      "data": <URL OBJECT>
    }

Domains (Функции для работы с доменами)
---------------------------------------

GET /domains/{domain}
~~~~~~~~~~~~~~~~~~~~~

Получение информации об Internet-домене.

|GET| ``https://www.virustotal.com/api/v3/domains/{domain}``


GET /domains/{domain}/comments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Получение комментариев для Internet-домена.

|GET| ``https://www.virustotal.com/api/v3/domains/domain/comments``


POST /domains/{domain}/comments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Добавление комментария для Internet-домена.

|POST| ``https://www.virustotal.com/api/v3/domains/domain/comments``

.. _domains-relationship-label:

GET /domains/{domain}/{relationship}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Получение объектов, связанных с Internet-доменом.

|GET| ``https://www.virustotal.com/api/v3/domains/{domain}/{relationship}``


GET /domains/{domain}/votes
~~~~~~~~~~~~~~~~~~~~~~~~~~~

|GET| ``https://www.virustotal.com/api/v3/domains/{domain}/votes``


POST /domains/{domain}/votes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Добавить голос за имя хоста или домена.

|POST| ``https://www.virustotal.com/api/v3/domains/{domain}/votes``


.. |POST| image:: https://i.imgur.com/CWgYjh1.png
.. |GET| image:: https://i.imgur.com/CBcN0Fh.png

