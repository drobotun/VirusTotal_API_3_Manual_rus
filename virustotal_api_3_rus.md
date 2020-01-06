![](https://i.imgur.com/6nji8Ec.png)

# Содержание

[**Вступление**](#intro)

- [Краткий обзор](#overview)
- [Различия публичного и premium API](#public_API_vs_premium_API)
- [Начало работы](#getting_started)
- [Аутентификация](#authentication)
- [Ответы API](#API_responses)
- [Ошибки](#errors)
- [Ключевые концепции](#key_concepts)
- [Объекты](#objects)
- [Коллекции](#collections)
- [Отношения](#relationships)

[**Объекты API**](#objects_api)

- [Файлы (files)](#files_obj)
	- [androguard](#androguard)
	- [asf_info](#asf_info)
	- [authentihash](#authentihash)
	- [bundle_info](#bundle_info)
	- [class_info](#class_info)
	- [deb_info](#deb_info)
	- [dmg_info](#dmg_info)
	- [dot_net_guids](#dot_net_guids)
	- [elf_info](#elf_info)
	- [exiftool](#exiftool)
	- [image_code_injections](#image_code_injections)
	- [ipa_info](#ipa_info)
	- [isoimage_info](#isoimage_info)
	- [jar_info](#jar_info)
	- [macho_info](#macho_info)
	- [magic](#magic)
	- [office_info](#office_info)
	- [openxml_info](#openxml_info)
	- [packers](#packers)
	- [pdf_info](#pdf_info)
	- [pe_info](#pe_info)
	- [rombios_info](#rombios_info)
	- [rtf_info](#rtf_info)
	- [signature_info](#signature_info)
	- [ssdeep](#ssdeep)
	- [swf_info](#swf_info)
	- [trid](#trid)
- [Поведение файлов (file behaviour)](#file_behaviour)
	- [DnsLookup](#DnsLookup)
	- [DroppedFile](#DroppedFile)
	- [BehaviourTag](#BehaviourTag)
	- [FileCopy](#FileCopy)
	- [HttpConversation](#HttpConversation)
	- [IpTraffic](#IpTraffic)
	- [PermissionCheck](#PermissionCheck)
	- [Process](#Process)
	- [Sms](#Sms)
	- [VerdictTag](#VerdictTag)
- [Домены (domains)](#domains)
	- [communicating_files](#communicating_files)
	- [downloaded_files](#downloaded_files)
	- [graphs](#graphs)
	- [referrer_files](#referrer_files)
	- [resolutions](#resolutions)
	- [siblings](#siblings)
- [IP-адреса (IP addresses)](#IP_addresses)
- [URL (URLs)](#URLs)
- [Представления (submissions)](#submissions)
- [Скриншоты (screenshots)](#screenshots)
- [Голоса (votes)](#votes)

[**Основные конечные точки API**](#endpoints)

- [files](#files_api)
	- [**POST** /files](#post_files)
	- [**GET** /files/upload_url](#get_files_upload_url)
	- [**GET** /files/{id}](#get_files_id)
	- [**POST** /files/{id}/analyse](#post_files_analyse)
	- [**GET** /files/{id}/comments](#get_files_comments)
	- [**POST** /files/{id}/comments](#post_files_comments)
	- [**GET** /files/{id}/votes](#get_files_votes)
	- [**POST** /files/{id}/votes](#post_files_votes)
	- [**GET** /files/{id}/{relationship}](#get_files_relationship)
	- [**GET** /file_behaviours/{sandbox_id}/pcap](#get_file_behaviours)
- [URLs]()
	- [**POST** /urls](#post_urls)
	- [**GET** /urls/{id}](#get_urls_id)
	- [**POST** /urls/{id}/analyse](#post_urls_analyse)
	- [**GET** /urls/{id}/comments](#get_urls_comments)
	- [**POST** /urls/{id}/comments](#post_urls_comments)
	- [**GET** /urls/{id}/votes](#get_urls_votes)
	- [**POST** /urls/{id}/votes](#post_urrls_votes)
	- [**GET** /urls/{id}/network_location](#get_urls_network_location)
	- [**GET** /urls/{id}/{relationship}](#get_urls_relationship)

# <a name="intro"> Вступление </a>

## <a name="overview"> Краткий обзор </a>

VirusTotal API 3 версии на данный момент находится в стадии бета-версии. Данная версия заменит [VirusTotal API 2 версии](https://developers.virustotal.com/v2.0) с течением определенного времени. Версия 3 VirusTotal API основана на спецификации [http://jsonapi.org/](http://jsonapi.org/) и была разработана с учетом простоты использования и единообразия.

VirusTotal API 3 версии следует принципам REST и имеет предсказуемые, ориентированные на ресурсы URL-адреса. В этой версии API для запросов и ответов (в том числе и ответов с информацией об ошибках) используется JSON.

>##### :warning: Важное замечание
>VirusTotal API 3 версии уже достаточно стабилен, однако некоторые несовместимые изменения по-прежнему возможны. Мы рекомендуем вам начать использовать его для экспериментов и не критически важных проектов.


## <a name="public_API_vs_premium_API"> Различия публичного и premium API </a>

Хотя многие функции, предоставляемые API VirusTotal, свободно доступны всем зарегистрированным пользователям, некоторые из них доступны только нашими премиум-клиентами. Эти функции составляют VirusTotal Premium API, и они будут соответствующим образом идентифицированы в этом описании.

Premium API - это компонент [расширенных сервисов VirusTotal для профессионалов](https://www.virustotal.com/gui/services-overview).

Публичный (открытый) API, с другой стороны, представляет собой набор функций, доступных для всех пользователей без каких-либо затрат. Единственное, что вам нужно для использования открытого API, это зарегистрироваться в сообществе VirusTotal и получить ключ API, как описано в разделе ["Начало работы"](#getting_started).

>##### Ограничения публичного API
>- Публичный API ограничен 4 запросами в минуту и 1000 запросами в день.
>- Публичный API не должен использоваться в коммерческих продуктах или услугах.
>- Публичный API не должен использоваться в бизнес-процессах, которые не вносят новых файлов.

>##### Основные моменты Premium API
>- Premium API не имеет ограничений по скорости запросов или суточных ограничений. Ограничения регулируются SLA (соглашением об уровне услуг).
>- Premium API возвращает больше данных об угрозах и предоставляет больше функциональных возможностей.
>- Premium API регулируется SLA (соглашением об уровне услуг), который гарантирует готовность данных.

Premium API имеет следующие **преимущества перед публичным API:**

- Позволяет выбрать частоту запросов и суточную квоту, которая наилучшим образом соответствует вашим потребностям.
- Позволяет загружать образцы для дальнейшего исследования, а также данные о сетевом трафике, которые они генерируют при выполнении, и подробные отчеты о выполнении.
- Возможно получение дополнительной информации об объектах, обработанных VirusTotal, например: предупреждения потока кода VBA для документов, исходные метаданные, выходные данные ExifTool, выходные данные IDS для зарегистрированных сетевых трасс, рейтинги популярности доменов, сертификаты SSL и т. д.
- Включает метаданные, сгенерированные исключительно VirusTotal: первая дата отправки файла, список имен файлов, с которыми файл был отправлен в VirusTotal, страны отправки, распространенность и т. д.
- Предоставит вам доступ к информации о поведении файлов, созданной в результате выполнения Windows PE, DMG, Mach-O и APK файлов в виртуализированной среде песочницы.
- Предоставляет сведения о "белых списках" и [доверенных источниках](http://blog.virustotal.com/2015/02/a-first-shot-at-false-positives.html).
- Позволяет задавать правила для запросов образцов, например: образцы с определенной сигнатурой; образцы, которые обнаружены более чем 10 антивирусными движками; образцы, которые содержат нужный раздел PE с определенным хэшем и т.д. Эти модификаторы поиска могут быть объединены для создания сложных запросов.
- Позволяет задавать правила для запросов URL, доменов, IP-адресов, например: все домены, зарегистрированные одним и тем же злоумышленником; все домены с TTL записи DNS A менее 5 секунд и т.д.
- Предоставляет возможность кластеризации файлов и поиска похожих файлов.
- Показывает расширенные связи, которые недоступны в публичном API, например: встроенные домены; встроенные IP-адреса; контактные домены и т. д.
- Позволяет программно взаимодействовать с VT Hunting, включая получение уведомлений о правилах YARA или автоматический запуск заданий ретро-поиска.
- Имеет строгое соглашение о предоставлении услуг (SLA), которое гарантирует доступность и готовность данных.

В частности, Premium API поддерживает следующие **основные варианты использования:**

- Автоматизация рабочих процессов с помощью набора данных VirusTotal, включая программное расширение предупреждений.
- Интеграция VirusTotal с вашим SIEM, SOAR, EDR или AV для целей расширения получаемой информации, а не обнаружения.
- Скачивание файлов для дальнейшего изучения в автономном режиме.
- Полная характеристика любого вида угрозы, которую можно наблюдать: файлы, URL-адреса, Домены, IP-адреса, SSL-сертификаты и т. д.

## <a name="getting_started"> Начало работы </a>

Для использования API необходимо зарегистрироваться в сообществе [VirusTotal Community](https://www.virustotal.com/gui/join-us). Как только у вас будет действительная учетная запись VirusTotal Community, вы найдете свой личный ключ доступа к API в разделе личных настроек. Этот ключ - все, что вам нужно для использования VirusTotal API.

>##### :warning: Важно!
>VirusTotal API не должен использоваться в коммерческих продуктах или услугах, он не может использоваться в качестве замены антивирусных продуктов и не может быть интегрирован в любой проект, который может нанести прямой или косвенный ущерб антивирусной индустрии. Несоблюдение этих условий приведет к немедленному запрету доступа нарушителя к VirusTotal API.
>
>При любых обстоятельствах [Условия предоставления услуг](https://support.virustotal.com/hc/en-us/articles/115002145529-Terms-of-Service) и [Политика конфиденциальности](https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy) VirusTotal должны соблюдаться.

По умолчанию любой зарегистрированный пользователь VirusTotal Community имеет право на ключ API, который позволяет ему взаимодействовать с базовым набором функций API. Расширенные вызовы доступны через Premium API, который требует специальных привилегий. [Свяжитесь с нами](https://www.virustotal.com/gui/contact-us/premium-services), если вы хотите узнать больше о том, как получить доступ к  Premium API.

## <a name="authentication"> Аутентификация </a>

Для аутентификации с помощью API вы должны включить заголовок x-apikey со своим личным ключом API во все ваши запросы. Ваш ключ API можно найти в пользовательском меню вашей учетной записи VirusTotal:

![pict_1](https://i.imgur.com/tby8XLV.png)

Ваш ключ доступа к API несет все ваши привилегии, поэтому держите его в безопасности и не делитесь им ни с кем. Всегда используйте HTTPS вместо HTTP для выполнения ваших запросов.

## <a name="api_responses"> Ответы API </a>

В большинстве случаев ресурс VirusTotal API возвращает ответ в формате JSON. Если не указано иное, ответ на успешный запрос будет иметь следующий формат:

##### Структура ответа
```
{
  "data": "<response data>"
}
```
`<response data>` обычно представляет собой объект или список объектов, однако это не всегда так. Примером этого является функция `/files/upload_url`, которая возвращает URL-адрес.

## <a name="errors"> Ошибки </a>

API VirusTotal следует обычным кодам ответа HTTP для указания успеха или неудачи. Коды в диапазоне `2xx` указывают на успех. Коды в диапазоне `4xx` указывают на ошибку в запросе (например, отсутствует параметр или ресурс не найден). Коды в диапазоне `5xx` указывают на ошибку на серверах VirusTotal, что бывает крайне редко.

Неудачные запросы возвращают дополнительную информацию об ошибке в формате JSON:

##### Формат ответа в случае ошибки
```
{
  "error": {
    "code": "<error code>",
    "message": "<a message describing the error>"
  }
}
```
Код ошибки `code` представляет собой строку с одним из значений, приведенных в ниже.

Сообщение `message` содержит ,более подробную информацию об ошибке.

- **409** - Ошибка типа "AlreadyExistsError". Ресурс уже существует.
- **401** - Ошибка типа "AuthenticationRequiredError". Выполнение операции возможно аутентифицированным пользователем. Убедитесь, что вы предоставили свой ключ доступа к API.
- **400** - Ошибка типа "BadRequestError". Запрос API является недопустимым или неправильным.
- **403** - Ошибка типа "ForbiddenError". Выполнение запрошенной операции невозможно.
- **400** - Ошибка типа "InvalidArgumentError". Некоторые аргументы, переданные в запросе неверные.
- **404** - Ошибка типа "NotFoundError" - Запрошенный ресурс не найден.
- **429** - Ошибка типа "QuotaExceededError". Превышение одной из квот на число запросов(минутной, ежедневной или ежемесячной). Ежедневные квоты сбрасываются каждый день в 00: 00 UTC.
- **429** - Ошибка типа "TooManyRequestsError". Большое число запросов.
- **401** - Ошибка типа "UserNotActiveError". Учетная запись пользователя не активна.
- **401** - Ошибка типа "WrongCredentialsError".- Ключ доступа к API является неверным.
- **503** - Ошибка типа "TransientError". Временная ошибка сервера. Повторная попытка запроса может сработать.

## <a name="key_concepts"> Ключевые концепции </a>

VirusTotal API (версии 3) базируется на трех ключевых понятиях: [объекты](#objects) (`objects`), [коллекции](#collections) (`collections`) и [отношения](#relationships) (`relationships`). Объект - это любой элемент, который может быть получен или обработан с помощью API. Файлы, URL-адреса, доменные имена и наборы правил поиска VirusTotal - это некоторые типы объектов, предоставляемые API.

Коллекция - это набор объектов. Объекты в коллекции обычно имеют один и тот же тип, но есть несколько исключений из этого правила. Некоторые операции API выполняются с объектами, а некоторые - с коллекциями.

Отношения - это связи между объектами, например: файл может быть связан с другим файлом, потому что один из файлов является ZIP-архивом, который содержит другой файл, URL-адрес может быть связан с файлом, потому что файл был загружен с URL-адреса, доменное имя связано со всеми URL-адресами в этом домене.

## <a name="objects"> Объекты </a>

Объект является ключевым понятием в API VirusTotal. Каждый объект имеет идентификатор и тип. Идентификаторы уникальны среди объектов одного типа. Это означает, что пара (тип, идентификатор) однозначно идентифицирует любой объект в API. В этой документации эти пары (тип, идентификатор) называются дескрипторами объектов.

Каждый объект имеет связанный с ним URL-адрес со следующей структурой:
```
https://www.virustotal.com/api/v3/{collection name}/{object id}
```
Обычно `{collection name}` - это множественная форма типа объекта, например, `files` - это коллекция, содержащая все объекты типа `file`, а `analyses` - это коллекция, содержащая все объекты `analysis`. Формат `{object id}` варьируется от одного типа объекта к другому.

GET-запрос на URL объекта возвращает информацию об этом объекте в следующем формате:

##### Пример ответа
```
{
  "data": {
    "type": "{object type}",
    "id": "{object id}",
    "links": {
      "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}"
    },
    "attributes" : {
      "integer_attribute": 1234,
      "string_attribute": "this is a string",
      "dictionary_attribute": { "one": 1, "two": 2 },
      "list_attribute": [ "foo", "bar", "baz" ]
    },
    "relationships" : {
       ..
    }
  } 
}	
```
Помимо идентификатора и типа, объект имеет набор атрибутов и отношений. Атрибуты могут быть любого типа, поддерживаемого JSON, включая списки и словари. Поле `attributes` всегда присутствует во всех объектах, а поле `relationships` является необязательными, в зависимости от того, просили ли вы включить данное поле при отправке запроса. Данный вопрос будет подробно обсуждаться в разделе ["Отношения"](#relationships).

Каждый тип объекта имеет свой собственный заранее определенный набор атрибутов, вы не сможете добавлять или удалять атрибуты, вы можете только изменять значения существующих (в случае если они доступны для записи). Для изменения значений атрибутов объекта необходимо отправить PATCH-запрос по URL объекта. Если вы попытаетесь изменить атрибут только для чтения, вы получите сообщение об ошибке. PATCH-запрос должен содержать атрибуты, которые вы хотите изменить в структуре, подобной той, что показана в приведенном ниже примере. Любой атрибут, не включенный в запрос, останется неизменным.

##### Пример PATCH-запроса
```
{
  "data": {
    "type": "{object type}",
    "id": "{object id}",
    "attributes" : {
      "integer_attribute": 1234,
      "string_attribute": "this is a new string",
    }
  } 
}
```
Обратите внимание, что идентификатор `id` и тип объекта `object` включены в PATCH-запрос, и они должны соответствовать указанным в URL.

Некоторые типы объектов также можно удалить, отправив DELETE-запрос на удаление по URL объекта.

## <a name="collections"> Коллекции </a>

Коллекции - это наборы объектов. Для большинства типов объектов существует коллекция верхнего уровня, представляющая все объекты этого типа. Доступ к этим коллекциям можно получить с помощью URL-адреса, например:
```
https://www.virustotal.com/api/v3/{collection name}
```
Большинство операций в API VirusTotal осуществляется путем отправки запросов к коллекции. Например, вы можете проанализировать файл, отправив POST-запрос в `/api/v3/files`, который успешно добавит новый элемент в коллекцию файлов. Вы можете создать новый набор правил VT Hunting, отправив POST-запрос в `/api/v3 /intelligence/hunting_rulesets`. Отправка POST-запроса в коллекцию обычно приводит к созданию новых объектов.

Аналогично, DELETE-запрос, отправляемый в коллекцию, приводит к удалению всех объектов в этой коллекции. Конечно, для определенных коллекций, таких как `files`, `urls` или `analyses` нет метода DELETE для запросов, но вы можете использовать DELETE-запрос с `/api/v3/intelligence/hunting_notifications`, который, как вы уже поняли, удаляет все ваши уведомления VT Hunting.

Большинство коллекций являются итеративными, вы можете извлечь все объекты в коллекции, отправив в коллекцию последовательные GET-запросы. На каждый запрос вы получаете ряд объектов и курсор `cursor`, который можно использовать для продолжения итерации. Приведенный ниже фрагмент иллюстрирует ответ на GET-запрос на `/api/v3/{collection name}`.

##### Пример ответа коллекции
```
{
    "data": [
      { .. object 1 .. },
      { .. object 2 .. },
      { .. object 3 .. }
    ],
    "meta": {
      "cursor": "CuABChEKBGRhdGUSCQjA1.."
    },
    "links": {
        "next": "https://www.virustotal.com/api/v3/{collection name}?cursor=CuABChEKBGRhdGUSCQjA1..",
        "self": "https://www.virustotal.com/api/v3/{collection name}"
    }
}
```
Как следует из поля `next` в разделе` links`, вы можете использовать `cursor` в качестве параметра при последующем вызове для получения следующего набора объектов. Вы также можете использовать параметр `limit` для управления количеством объектов, возвращаемых при каждом вызове.

## <a name="relationships"> Отношения </a>

Отношения - это способ, которым API-интерфейс VirusTotal выражает связи или зависимости между объектами. Объект может быть связан с объектами того же или другого типа. Например, файловый объект может быть связан с некоторым другим файловым объектом, который содержит первый, или файловый объект может быть связан с объектами URL, представляющими URL, встроенные в файл.

Отношения могут быть вида "один к одному" или "один ко многим", в зависимости от того, связан объект с одним объектом или с несколькими объектами.

При извлечении какого-либо объекта с помощью GET-запроса можно также получить его связи с другими объектами. Это можно сделать, указав отношение, которое вы хотите получить в параметре `relationships`:
```
https://www.virustotal.com/api/v3/{collection name}/{object id}?relationships={relationship}
```
Можно указать несколько отношений в параметре `relationships`, перечислив их имена через запятую:
```
https://www.virustotal.com/api/v3/{collection name}/{object id}?relationships={relationship 1},{relationship 2}
```
Объекты, возвращаемые такими запросами, включают словарь отношений, где ключи - это имена запрашиваемых отношений, а значения - это либо дескриптор объекта (если отношение одно к одному), либо коллекция, как описано в разделе ["Коллекции"](#collections) (если отношение одно ко многим). Однако обратите внимание, что эти коллекции содержат не все связанные объекты, а только их дескрипторы (т. е. их тип и идентификатор).

##### Отношения в объекте

```
{
  "type": "{object type}",
  "id": "{object id}",
  "links": {
    "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}"
  },
  "attributes" : {
     ..
  },
  "relationships" : {
     "{one-to-one relationship}": {
       "data": {
         "id": "www.google.com",
         "type": "domain"
       },
       "links": {
         "related": "https://www.virustotal.com/api/v3/{collection name}/{object id}/{one-to-one relationship}",
         "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{one-to-one relationship}"
       }
     },
     "{one-to-many relationship}": {
       "data": [
         { .. object descriptor 1 .. },
         { .. object descriptor 2 .. },
         { .. object descriptor 3 .. }
       ],
       "meta": {
         "cursor": "CuABChEKBGRhdGUSCQjA1LC...",
       },
       "links": {
         "next": "https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{one-to-many relationship}?cursor=CuABChEKBGRhdGUSCQjA1LC...",
         "self": "https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{one-to-many relationship}"
       },
     },
    "{relationship 2}": { ... },
    "{relationship 3}": { ... }
  }
}
```
Если вы внимательно посмотрите на поле `links` для связи в приведенном выше примере, вы увидите, что URL в поле `self` выглядит следующим образом:
```
https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{relationship}
```
Отношения "один ко многим" - это просто коллекции, содержащие объекты, которые каким-то образом связаны с основным объектом, поэтому они обычно имеют свой собственный URL, который можно использовать для перебора связанных объектов, отправляя GET-запросы на этот URL, как описано в разделе ["Коллекции"](#collections). При этом имеется два URL-адреса:
```
https://www.virustotal.com/api/v3/{collection name}/{object id}/relationships/{relationship}
https://www.virustotal.com/api/v3/{collection name}/{object id}/{relationship}
```
Первый URL - это коллекция, содержащая только дескрипторы (тип и идентификатор) для связанных объектов, второй - полные объекты со всеми их атрибутами. Если вас интересует только тип и идентификатор связанных объектов, вы должны использовать первый, так как более эффективно извлекать только дескрипторы, чем полные объекты.

Еще одно важное различие между обеими конечными точками заключается в том, что `{object id}/relationships/{relationship}` представляет отношение как независимую сущность и может поддерживать операции, которые изменяют отношение без изменения объектов. Напротив, `{object id}/{relationship}` представляет связанные объекты, а не отношение. Например, если вы хотите предоставить пользователю разрешения на просмотр графика, вы можете использовать:
```
POST https://www.virustotal.com/api/v3/graphs/{id}/relationships/viewers
```
Эта конечная точка получает пользовательский дескриптор, она не изменяет ни пользователя, ни график, она просто создает связь между ними. С другой стороны, когда вы создаете новый комментарий для файла, вы используете:
```
POST https://www.virustotal.com/api/v3/files/{id}/comments
```
И в этом случае вы не только изменяете связь между файлом и комментарием, но и создаете новый объект комментария.
# <a name="objects_api"> Объекты API </a>

## <a name="files_obj"> Файлы (files) </a>

Файлы являются одним из наиболее важных типов объектов в VirusTotal API. У нас есть огромный набор данных из более чем 2 миллиардов файлов, которые были проанализированы VirusTotal на протяжении многих лет. Объект `file` может быть получен либо путем загрузки нового файла в VirusTotal, либо путем поиска уже существующего хэша файла, либо другими способами при поиске в службах VT Enterprise services. В объекте `file` вы найдете некоторые релевантные базовые атрибуты о файле и его связи с VirusTotal:

- хэш-суммы файлов, такие как `md5`, `sha1` и `sha256`, которые однозначно идентифицируют файл;
- `size` - размер файла;
- `first_submission_date` - дата и время когда файл был впервые получен в VirusTotal (как временная метка UNIX);
- `last_analysis_date` - дата и время последнего анализа файла (как временная метка UNIX);
- `last_modification_date` - дата и время последнего изменения файла (как временная метка UNIX);
- `times_submitted` - число загрузок файла на сервер;
- `last_analysis_results` - результаты последнего анализа;
- `names` - имя файла `meaningful_name`, которое мы считаем наиболее содержательным;
- `downloadable` - показывает возможность скачивания файла с сервера;
- `unique_sources` - указывает, из скольких различных источников был получен файл.

##### JSON
```
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
```
В словаре атрибутов присутствует также поля с информацией, извлеченной из самого файла. Эта информация раскрыта в следующих ключах:

- `type_description` - описание типа файла, с коротким его представлением `type_tag`, который можно использовать для поиска файлов этого типа;
- `creation_date` - извлекается, когда это возможно, из файла и указывает метку времени компиляции или сборки, может быть подделан создателями вредоносных программ;
- `total_votes` - общее количество голосов по результатам голосования пользователей VirusTotal Community. Поле `reputation` рассчитывается на основе голосов, полученных файлом, и репутации пользователей;
- `vhash` - значение т. н. нечеткого хэша, определяемого по алгоритму кластеризации, основанного на простом структурном хэше признаков, и который позволяет находить похожие файлы;
- `tags` - извлекаются из разных частей отчета и являются метками, которые помогают вам искать похожие образцы.

##### JSON
```
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
```
Кроме того, VirusTotal вместе с каждым антивирусным сканированием запускает набор утилит, позволяющих собирать дополнительную информацию о файле. Вся эта информация содержится в поле `attributes` вместе с остальными ранее описанными полями.

### <a name="androguard"> androguard </a>
#### Информация об Android файлах

`androguard` показывает информацию о файлах Android APK, DEX и XML, извлеченных с помощью утилиты Androguard.

- `Activities` - список активностей (activities) приложения;
- `AndroguardVersion` - версия используемой утилиты Androguard;
- `AndroidApplication` - тип файла Android в формате целого числа;
- `AndroidApplicationError` - логическое переменная со значением `False`;
- `AndroidApplicationInfo` - тип файла Android ("APK"," DEX","XML");
- `AndroidVersionCode` - код версии Android, считанный из манифеста;
- `AndroidVersionName` - имя версии Android, считанное из манифеста;
- `Libraries` - список библиотек, используемых приложением;
- `Main Activity` - название основной активности (activitie), прочитанное из манифеста;
- `MinSdkVersion` - минимальная поддерживаемая версия SDK;
- `Package` - имя пакета, считанное из манифеста;
- `Permissions` - словарь с разрешениями, используемыми в качестве ключа и списка с 3 элементами в качестве значения:
	- тип разрешения (например, `normal`, `dangerous`);
	- короткий дескриптор разрешения;
	- дескриптор разрешения;
- `Providers` - список провайдеров (providers), используемых приложением;
- `Receivers` - список получателей (receivers), используемых приложением;
- `RiskIndicator` - словарь с показателями риска `APK` (structure) и `PERM` (permissions):
	- `APK` - показывает используемые компоненты и их количество (например, `"EXECUTABLE": 3`);
	- `PERM` - показывает типы разрешений и их количество (например, `"DANGEROUS": 11`);
- `Services` - список служб (services), используемых приложением;
- `StringsInformation` - список примечательных строк, найденных в приложении;
- `TargetSdkVersion` - версия Android, на которой приложение было протестировано;
- `VTAndroidInfo` - версия Androguard, используемая сервисом VirusTotal;
- `certificate` - сведения о сертификате приложения в виде словаря с полями:
	- `Issuer` - словарь с отличительными (уникальными) именами и значениями. Типичными записями являются `DN` (отличительное (уникальное) имя), `CN` (общее имя), `O` (организация);
	- `Subject` - словарь с RDN (перечнем уникальных имен) эмитента сертификата;
	- `serialnumber` - серийный номер сертификата;
	- `thumbprint` - хэш сертификата в шестнадцатеричном виде;
	- `validfrom` - дата начала действия сертификата в [формате](http://strftime.org/) "%H:%M %p %m/%d/%Y";
	- `validto` - срок действия сертификата, в формате "%H:%M %p %m/%d/%Y";
- `intent-filters` - фильтр предполагаемых действий приложения исходя из активностей (activities), получателей (receivers) и служб (services).

##### Информация об APK файлах в виде JSON
```
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
```

### <a name="asf_info"> asf_info </a>
#### Информация о Microsoft Advanced Streaming/Systems Format (ASF) файлах

`asf_info` показывает информацию о Microsoft ASF files (.asf, .wma, .wmv).

- `content_encryption_object` - информация о том, как зашифрован файл:
	- `key_id` - ID тиспользуемого ключа;
	- `license_url` - url-адрес лицензии;
	- `protection_type` - тип используемой защиты (например, "DRM");
	- `secret_data` - байты, содержащие секретные данные;
- `extended_content_encryption_object` - расширенная информация о том, как зашифрован файл:
	- `CHECKSUM` - контрольная сумма данных;
	- `KID` - ID тиспользуемого ключа;
	- `EncodeType` - тип кодирования;
	- `LAINFO` - информация о лицензионном соглашении;
	- `DRMHeader` - заголовок, используемый в DRM;
- `script_command_objects` - скрипты, используемые в файле:
	- `action` - действие, которое необходимо выполнить;
	- `type` - тип действия (например, `URL`, `FILENAME`, `EVENT`);
	- `trigger_time` - время активации скрипта.

##### Информация об ASF файлах в виде JSON
```
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
```

### <a name="authentihash"> authentihash </a>
#### Хэш для проверки PE-файлов

`authentihash` - это хэш sha256, используемый корпорацией Microsoft для проверки того, что соответствующие разделы образа PE-файла не были изменены.

##### JSON
```
{
  "data": {
		...
    "attributes" : {
      ...
      "authentihash": "<string>",
    }
  }
}
```

### <a name="bundle_info"> bundle_info </a>
#### Информация о сжатых файлах

`bundle_info` предоставляет информацию о сжатых файлах (ZIP, TAR, GZIP и т. д.).

- `beginning` - распакованный заголовок файла для некоторых форматов файлов (GZIP, ZLIB);
- `extensions` - расширения файлов и их количество внутри пакета;
- `file_types` - типы файлов и их количество внутри пакета;
- `highest_datetime` - самая последняя дата в содержащихся файлах, в [формате](http://strftime.org/) "%H:%M %p %m/%d/%Y";
- `lowest_datetime` - самая старая дата в содержащихся файлах, в формате "%H:%M %p %m/%d/%Y";
- `num_children` - сколько файлов и каталогов находится внутри пакета;
- `tags` - интересные замечания о содержании (например, `"contains-pe"`);
- `type` - тип пакета (например, "ZIP");
- `uncompressed_size` - несжатый размер содержимого внутри сжатого файла;
- `vhash` - хэш подобия (нечеткий хэш) для этого типа файлов.

##### Информация о сжатых файлах в виде JSON
```
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
```

### <a name="class_info"> class_info </a>
#### Информация о классах Java в байткод-файлах

`class_info` предоставляет информацию о Java байткод-файлах.

- `constants` - константы, используемые в классе;
- `extends` -  класс, от которого наследован данный класс;
- `implements` - интерфейсы реализованные в классе;
- `methods` - методы, принадлежащие к классу;
- `name` - имя класса;
- `platform` - платформа в виде строки, полученной из старшего и младшего номера версии;
- `provides` - представленные классы, поля и методы;
- `requires` - обязательные классы, поля и методы.

##### Информация о Java классе в виде JSON
```
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
```

### <a name="deb_info"> deb_info </a>
#### Информация о Debian пакетах

`deb_info` - предоставляет информацию о [Debian пакетах](https://wiki.debian.org/Packaging).

- `changelog` - информация об изменениях в версии пакета:
	- `Author` - имя автора;
	- `Date` дата в [формате](http://strftime.org/) "%a, %d %b %Y %H:%M%S %z";
	- `Debian revision` - ревизия;
	- `Debian version` - версия;
	- `Distributions` - тип распространения;
	- `Full version` - полная версия системы;
	- `Package` - тип пакета;
	- `Urgency` - уровень срочности изменений;
	- `Version history` - история версий;
- `control_metadata` - общие (неизменные) поля пакета:
	- `Maintainer` - идентификатор того, кто осуществляет поддержку пакета;
	- `Description` - дескриптор пакета;
	- `Package` - имя пакета;
	- `Depends` - зависимости пакета;
	- `Version` - версия пакета;
	- `Architecture` - архитектура для запуска этого пакета (например, `"i386"`);
- `control_scripts` - сценарии для запуска в операциях управления пакетами:
	- `postinst` - скрипт, выполняемый после инсталляции;
	- `postrm` - скрипт, выполняемый после удаления пакета;
- `structural_metadata`:
	- `contained_files` - количество файлов в пакете;
	- `contained_items` - количество пунктов в пакете;
	- `max_date` - дата самого старого файла в формате "%Y-%m-%d %H:%M%S";
	- `min_date` - самая последняя дата файла в формате "%Y-%m-%d %H:%M%S".

##### Информация о Debian пакете в виде JSON
```
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
```

### <a name="dmg_info"> dmg_info </a>
#### Информация о монтируемых образах дисков macOS


### <a name="dot_net_guids"> dot_net_guids </a>
#### Идентификаторы для сборок Microsoft .NET


### <a name="elf_info"> elf_info </a>
#### Информация о Unix ELF-файлах


### <a name="exiftool"> exiftool </a>
#### Информация о метаданных EXIF из файлов

### <a name="ipa_info"> ipa_info </a>
#### Информация об iOS App Store Package файле


### <a name="isoimage_info"> isoimage_info </a>
#### Информация о файлах ISO=образов





# <a name="endpoint"> Основные конечные точки API </a>

## <a name="files_api"> Files </a>

Файлы являются одним из наиболее важных типов объектов в API VirusTotal. У нас есть огромный набор данных из более чем 2 миллиардов файлов, которые были проанализированы VirusTotal на протяжении многих лет. В этом разделе описываются конечные точки API для анализа новых файлов и получения информации о любом файле в нашем наборе данных.

### <a name="post_files"> POST /files </a>

Загрузка и анализ файла.

**POST:** `https://www.virustotal.com/api/v3/files`

##### cURL
```curl
curl --request POST \
  --url https://www.virustotal.com/api/v3/files \
  --header 'x-apikey: <your API key>' \
  --form file=@/path/to/file
```

##### Python
```python
api_url = "https://www.virustotal.com/api/v3/files"
headers = {"x-apikey" : "<ключ доступа к API>"}
with open("<путь к файлу>", "rb") as file:
    files = {"file": ("<путь к файлу>", file)}
    response = requests.post(api_url, headers=headers, files=files)
```

##### Параметры запроса

- **file** - файл для сканирования.

##### Заголовок запроса

- **x-apikey** - ключ доступа к API.

Файлы могут быть загружены в VirusTotal путем отправки POST-запросов, закодированных как `multipart/form-data` в конечную точку `https://www.virustotal.com/api/v3/files`. Каждый POST-запрос должен иметь поле с именем `file`, содержащее файл для анализа. Общий размер полезной нагрузки не может превышать 32 МБ. Для загрузки больших файлов см. [**GET** /files/upload_url](#get_files_upload_url).

Результат, возвращаемый этой функцией, является дескриптором объекта для нового анализа. Идентификатор, содержащийся в дескрипторе, можно использовать с конечной точкой [**GET** /analysis/{id}](#get_analyses_id) для получения информации о результатах анализа этого файла.

Для анализа файла, который ранее уже был загружен в VirusTotal, можно использовать [**POST** /fails/{id}/analyse](#post_files_analyse).

##### Пример ответа
```
{
  "data": {
    "type": "analysis",
    "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
  }
}
```
