[![](https://i.imgur.com/6nji8Ec.png)](https://www.virustotal.com)

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

- [**files**](#files_api)
	- [![](https://i.imgur.com/CWgYjh1.png) /files](#post_files)
	- [![](https://i.imgur.com/CBcN0Fh.png) /files/upload_url](#get_files_upload_url)
	- [![](https://i.imgur.com/CBcN0Fh.png) /files/{id}](#get_files_id)
	- [![](https://i.imgur.com/CWgYjh1.png) /files/{id}/analyse](#post_files_analyse)
	- [![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/comments](#get_files_comments)
	- [![](https://i.imgur.com/CWgYjh1.png) /files/{id}/comments](#post_files_comments)
	- [![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/votes](#get_files_votes)
	- [![](https://i.imgur.com/CWgYjh1.png) /files/{id}/votes](#post_files_votes)
	- [![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/download_url](#get_download_url)
	- [![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/download](#get_download)
	- [![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/{relationship}](#get_files_relationship)
	- [![](https://i.imgur.com/CBcN0Fh.png) /file_behaviours/{sandbox_id}/pcap](#get_file_behaviours)
- [**URLs**]()
	- [![](https://i.imgur.com/CWgYjh1.png) /urls](#post_urls)
	- [![](https://i.imgur.com/CBcN0Fh.png) /urls/{id}](#get_urls_id)
	- [![](https://i.imgur.com/CWgYjh1.png) /urls/{id}/analyse](#post_urls_analyse)
	- [![](https://i.imgur.com/CBcN0Fh.png) /urls/{id}/comments](#get_urls_comments)
	- [![](https://i.imgur.com/CWgYjh1.png) /urls/{id}/comments](#post_urls_comments)
	- [![](https://i.imgur.com/CBcN0Fh.png) /urls/{id}/votes](#get_urls_votes)
	- [![](https://i.imgur.com/CWgYjh1.png) /urls/{id}/votes](#post_urrls_votes)
	- [![](https://i.imgur.com/CBcN0Fh.png) /urls/{id}/network_location](#get_urls_network_location)
	- [![](https://i.imgur.com/CBcN0Fh.png) /urls/{id}/{relationship}](#get_urls_relationship)

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

>##### :information_source: Ограничения публичного API
>- Публичный API ограничен 4 запросами в минуту и 1000 запросами в день.
>- Публичный API не должен использоваться в коммерческих продуктах или услугах.
>- Публичный API не должен использоваться в бизнес-процессах, которые не вносят новых файлов.

>##### :information_source: Основные моменты Premium API
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

`dmg_info` сообщает данные о структуре [файлов Apple.dmg](https://en.wikipedia.org/wiki/Apple_Disk_Image). Большая часть данных поступает из метаданных внутренних файлов, которые могут содержаться в некоторых файлах, а в других - нет.

- `blkx` - список блоков в образе. Каждая запись содержит:
	- `attributes` - в формате шестнадцатеричного числа;
	- `name` - имя блока;
- `data_fork_length` - размер данных форка;
- `data_fork_offset` - смещение данных форка;
- `dmg_version` - версия DMG-файла;
- `hfs` - информация об HFS-элементах. В зависимости от конкретного случая могут присутствовать различные поля:
	- `info_plist` - содержимое списка свойств (plist) данного блока;
	- `main_executable` - основной исполняемый файл этого блока;
		- `id` - идентификатор;
		- `path` - путь в пакете;
		- `sha256` - хэш содержимого;
		- `size` - размер файла в байтах;
	- `num_files` - количество файлов;
	- `unreadable_files` - количество нечитаемых файлов;
- `plist` - содержит сведения о конфигурации приложения, такие как идентификатор пакета, номер версии и отображаемое имя;
- `plist_keys` - ключи от записи plist;
- `running_data_fork_offset` - смещение начала используемых данных форка (обычно 0);
- `resourcefork_keys` - ключи, найденные в ресурсах форка;
- `rsrc_fork_length` - длина ресурсов форка;
- `rsrc_fork_offset` - смещение ресурсов форка;
- `xml_lenght` - размер списка свойств в DMG;
- `xml_offset` - смещение списка свойств в DMG.

##### Apple .dmg-файл
```
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
```

### <a name="dot_net_guids"> dot_net_guids </a>
#### Идентификаторы для сборок Microsoft .NET

- `dot_net_guids` - список [идентификаторов для сборок Microsoft .NET](https://www.virusbulletin.com/virusbulletin/2015/06/using-net-guids-help-hunt-malware/);
- `mvid` - ModuleVersionID, генерируемый во время сборки, в результате чего для каждой сборки создается новый идентификатор GUID;
- `typelib_id` - TypeLibID (если имеется), созданный Visual Studio при создании нового проекта по умолчанию.

##### ID сборки Microsoft .NET в виде JSON
```
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
```

### <a name="elf_info"> elf_info </a>
#### Информация о Unix ELF-файлах

`elf_info` возвращает информацию о [Unix ELF file format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).

- `exports` - список экспортируемых элементов. Каждый элемент содержит имя и тип.
- `header` - некоторые описательные метаданные о файле:
	- `type` - тип файла (например "EXEC" (исполняемый файл);
	- `hdr_version` - версия заголовка;
	- `num_prog_headers` - количество записей в заголовке программы;
	- `os_abi` - тип бинарного интерфейса приложения (например "UNIX-Linux");
	- `obj_version` - `0x1` для оригинальных ELF-файлов;
	- `machine` - платформа (например "Advanced Micro Devices X86-64");
	- `entrypoint` - точка входа;
	- `num_section_headers` - число секций в заголовке;
	- `abi_version` - версия бинарного интерфейса приложения;
	- `data` - выравнивание данных в памяти (например "little endian");
	- `class` - класс файла (например "ELF32");
- `imports` - список импортируемых элементов. Каждый элемент содержит имя и тип;
- `sections` - секции ELF-файла:
	- `name` - имя секции;
	- `address` - виртуальный адрес секции;
	- `flags` - атрибуты секции;
	- `offset` - смещение секции;
	- `type` - тип секции;
	- `size` - размер секции в байтах;
- `segments` - они же заголовки программ. каждый элемент содержит тип сегмента и список ресурсов, задействованных в этом сегменте;
- `shared_libraries` - список общих библиотек, используемых этим исполняемым файлом.

##### Формат ELF-файла
```
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
```

### <a name="exiftool"> exiftool </a>
#### Информация о метаданных EXIF из файлов

`exiftool` это утилита для извлечения метаданных EXIF из файлов различных форматов. Представляемые метаданные могут различаться в зависимости от типа файла, и, учитывая природу метаданных EXIF, соcтав отображаемых полей может различаться.

Например:

- поля для Microsoft Windows PE-файлов:
```
CharacterSet, CodeSize, CompanyName, EntryPoint, FileDescription, FileFlagsMask,
FileOS, FileSize, FileSubtype, FileType, FileTypeExtension, FileVersion,
FileVersionNumber, ImageVersion, InitializedDataSize, InternalName, LanguageCode,
LegalCopyright, LinkerVersion, MIMEType, MachineType, OSVersion, ObjectFileType,
OriginalFileName,, PEType, ProductName, ProductVersion, ProductVersionNumber,
Subsystem, SubsystemVersion, TimeStamp, UninitializedDataSize
```
- поля для JPEG-файлов:
```
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
```
- поля для PDF_файла:
```
CreateDate, Creator, CreatorTool, DocumentID, FileType, FileTypeExtension,
Linearized, MIMEType, ModifyDate, PDFVersion, PageCount, Producer, XMPToolkit
```

##### JSON
```
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
```

### <a name="image_code_injections"> image_code_injections </a>
#### Инъекция кода в файл изображения

`image_code_injections` возвращает содержимое внедренного кода в файлах изображений.

##### JSON
```
{
  "data": {
		...
    "attributes" : {
      ...
      "image_code_injections": "<string>"
    }
  }
}
```

### <a name="ipa_info"> ipa_info </a>
#### Информация об iOS App Store Package файле


### <a name="isoimage_info"> isoimage_info </a>
#### Информация о файлах ISO=образов


### <a name="jar_info"> jar_info </a>
#### Информация о файлах Java Archive


### <a name="macho_info"> macho_info </a>
#### Информация о файлах Apple MachO


### <a name="magic"> magic </a>
#### Идентификация файлов по "магическому числу"

`magic` дает предположение о типе файла, основываясь на популярном инструменте синтаксического анализа из UNIX (команда `file`).

##### Предполагаемый тип файла
```
{
  "data": {
		...
    "attributes" : {
      ...
      "magic": "<string>",
    }
  }
}
```

### <a name="office_info"> office_info </a>
#### Информация о структуре файлов Microsoft Office


### <a name="openxml_info"> openxml_info </a>
#### Информация об Microsoft OpenXML файлах


### <a name="packers"> packers </a>
#### Информация об упаковщике, используемом в файле


### <a name="pdf_info"> pdf_info </a>
#### Информация об Adobe PDF файлах


### <a name="pe_info"> pe_info </a>
#### Информация о файлах формата Microsoft Windows Portable Executable


### <a name="rombios_info"> rombios_info </a>
#### Информация о BIOS, EFI, UEFI и связанны[ с ними архивах


### <a name="rtf_info"> rtf_info </a>
#### Информация о файлах формата Microsoft Rich Text


### <a name="signature_info"> signature_info </a>
#### Информация о подписи PE-файлов


### <a name="ssdeep"> ssdeep </a>
#### CTPH хэш содержимого файла


### <a name="swf_info"> swf_info </a>
#### Информация о Adobe Shockwave Flash файлах


### <a name="trid"> trid </a>
#### Тип файла идентифицированный с помощью утилиты [TrID](http://mark0.net/soft-trid-e.html)


## <a name="file_behaviour"> Поведение файлов (file behaviour) </a>


### <a name="DnsLookup"> DnsLookup </a>


### <a name="DroppedFile"> DroppedFile </a>


### <a name="BehaviourTag"> BehaviourTag </a>


### <a name="FileCopy"> FileCopy </a>


### <a name="HttpConversation"> HttpConversation </a>


### <a name="IpTraffic"> IpTraffic </a>


### <a name="PermissionCheck"> PermissionCheck </a>


### <a name="Process"> Process </a>


### <a name="Sms"> Sms </a>


### <a name="VerdictTag"> VerdictTag </a>


## <a name="domains"> Домены (domains) </a>


### <a name="communicating_files"> communicating_files </a>


### <a name="communicating_files"> communicating_files </a>


### <a name="downloaded_files"> downloaded_files </a>


### <a name="graphs"> graphs </a>


### <a name="referrer_files"> referrer_files </a>


### <a name="resolutions"> resolutions </a>


### <a name="siblings"> siblings </a>


## <a name="IP_addresses"> IP-адреса (IP addresses) </a>


## <a name="URLs"> URL (URLs) </a>


## <a name="submission"> Представления (submissions) </a>


## <a name="screenshots"> Скриншоты (screenshots) </a>


## <a name="votes"> Голоса (votes) </a>


# <a name="endpoints"> Основные конечные точки API </a>

## <a name="files_api"> Files </a>

Файлы являются одним из наиболее важных типов объектов в API VirusTotal. У нас есть огромный набор данных из более чем 2 миллиардов файлов, которые были проанализированы VirusTotal на протяжении многих лет. В этом разделе описываются конечные точки API для анализа новых файлов и получения информации о любом файле в нашем наборе данных.

### <a name="post_files"> ![](https://i.imgur.com/CWgYjh1.png) /files </a>

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
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files"
headers = {"x-apikey" : "<ключ доступа к API>"}
with open("<путь к файлу>", "rb") as file:
    files = {"file": ("<путь к файлу>", file)}
    response = requests.post(api_url, headers=headers, files=files)
```

##### Параметры запроса

- **file** - файл для сканирования.

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

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

### <a name="get_files_upload_url"> ![](https://i.imgur.com/CBcN0Fh.png) /files/upload_url </a>

Получение URL для загрузки файла больше 32 МБ.

**GET:** `https://www.virustotal.com/api/v3/files/upload_url`

##### cURL
```curl
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/upload_url \
  --header 'x-apikey: <your API key>'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/upload_url"
headers = {"x-apikey" : "<ключ доступа к API>"}
response = requests.get(api_url, headers=headers)
```

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Для загрузки файлов размером менее 32 МБ вы можете просто использовать конечную точку [**POST** /files](#post_files), но для файлов большего размера необъодимо сначала получить специальный URL загрузки, а затем отправить POST-запрос  на этот URL вместо отправки его в конечную точку **POST** /files. Этот POST-запрос должен иметь тот же формат, что и для конечной точки **POST** /files. Каждый полученный URL можно использовать только один раз.

>##### :information_source: Файлы размером более 200 МБ
>Обратите внимание, что файлы размером более 200 МБ, как правило, представляют собой пакеты какого-либо вида (сжатые файлы, ISO-образы и т. д.) в этих случаях имеет смысл загрузить внутренние файлы отдельно по нескольким причинам:
>- Движки некоторых антивирусов, как правило, имеют проблемы с производительностью при сканировании больших файлов (из-за больших тайм-аутов, некоторые из них могут даже не сканировать их);
>- Движки некоторых антивирусов не могут проверять определенные типы файлов, в то время как они смогут проверить внутренние файлы, если они будут отправлены;
>- При сканировании большого пакета вы теряете контекст, в котором конкретный внутренний файл вызывает обнаружение.

##### Пример ответа
```
{
  "data": "http://www.virustotal.com/_ah/upload/AMmfu6b-_DXUeFe36Sb3b0F4B8mH9Nb-CHbRoUNVOPwG/"
}
```

### <a name="get_files_id"> ![](https://i.imgur.com/CBcN0Fh.png) /files/{id} </a>

Получение информации о файле.

**GET:** `https://www.virustotal.com/api/v3/files/{id}`

##### cURL
```curl
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{id} \
  --header 'x-apikey: <your API key>'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}"
headers = {"x-apikey" : "<ключ доступа к API>"}
response = requests.get(api_url, headers=headers)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

##### Пример ответа
```
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
```

### <a name="post_files_analyse"> ![](https://i.imgur.com/CWgYjh1.png) /files/{id}/analyse </a>

Повторный анализ файла в VirusTotal/
>##### :warning: Осторожно!
>Эта функция API может привести к отказу в обслуживании инфраструктуры сканирования в случае неправильного использования. Пожалуйста, свяжитесь с нами, если вы собираетесь сканировать более 50 тысяч файлов в день.

**POST:** `https://www.virustotal.com/api/v3/files/{id}/analyse`

##### cURL
```curl
curl --request POST \
  --url https://www.virustotal.com/api/v3/files/{id}/analyse \
  --header 'x-apikey: <your API key>'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}/analyse"
headers = {"x-apikey" : "<ключ доступа к API>"}
response = requests.post(api_url, headers=headers)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Файлы, которые уже были загружены в VirusTotal, можно повторно проанализировать, не загружая их снова, используя эту функцию. Ответом является дескриптор объекта для нового анализа, как и в функции [**POST** /files](#post_files). Идентификатор, содержащийся в дескрипторе, можно использовать с функции [**GET** /analyses/{id}](#get_analyses_id) для получения информации о результатах анализа.

##### Пример ответа
```
{
  "data": {
    "type": "analysis",
    "id": "NjY0MjRlOTFjMDIyYTkyNWM0NjU2NWQzYWNlMzFmZmI6MTQ3NTA0ODI3Nw=="
  }
}
```

### <a name="get_files_comments"> ![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/comments </a>

Получение комментариев для файла

**GET:** `https://www.virustotal.com/api/v3/files/{id}/comments`

##### cURL
```curl
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{id}/comments \
  --header 'x-apikey: <your API key>'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}/comments"
headers = {"x-apikey" : "<ключ доступа к API>"}
query = {"limit": "<limit)>", "cursor": "<cursor>"}
response = requests.get(api_url, headers=headers, params=query)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **limit** - максимальное число комментариев в ответе (int_32, необязательный параметр);
- **cursor** - курсор продолжения (string, необязательный параметр).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

### <a name="post_files_comments"> ![](https://i.imgur.com/CWgYjh1.png) /files/{id}/comments </a>

Добавление комментария для файла.

**POST:** `https://www.virustotal.com/api/v3/files/{id}/comments`

##### cURL
```curl
curl --request POST \
  --url https://www.virustotal.com/api/v3/files/{id}/comments \
  --header 'x-apikey: <your API key>' \
  --data '{"data": {"type": "comment", "attributes": {"text": "Lorem ipsum dolor sit ..."}}}'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}/comments"
headers = {"x-apikey" : "<ключ доступа к API>"}
comments = {"data": {"type": "comment", "attributes": {"text": "Lorem ipsum dolor sit ..."}}}
response = requests.post(api_url, headers=headers, json=comments)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **data** - комментарий (json).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

С помощью этой функции вы можете опубликовать комментарий для данного файла. Тело POST-запроса должно быть JSON-представлением комментария. Обратите внимание, что вам не нужно указывать идентификатор объекта, так как он автоматически генерируется для новых комментариев.

Любое слово, начинающееся с `#` в тексте вашего комментария, будет считаться тегом и добавляться в атрибут тега комментария.

##### Пример запроса
```
{
  "data": {
    "type": "comment",
    "attributes": {
    	"text": "Lorem #ipsum dolor sit ..."
    }
  }
}
```

##### Пример ответа
```
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
```

### <a name="get_files_votes"> ![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/votes </a>

Получение результатов голосования для файла

**GET:** `https://www.virustotal.com/api/v3/files/id/votes`

##### cURL
```curl
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{id}/votes \
  --header 'x-apikey: <your API key>'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}/comments"
headers = {"x-apikey" : "<ключ доступа к API>"}
query = {"limit": "<limit)>", "cursor": "<cursor>"}
response = requests.get(api_url, headers=headers, params=query)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **limit** - максимальное число комментариев в ответе (int_32, необязательный параметр);
- **cursor** - курсор продолжения (string, необязательный параметр).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

### <a name="post_files_votes"> ![](https://i.imgur.com/CWgYjh1.png) /files/{id}/votes </a>

Добавление голоса для файла.

**POST:** `https://www.virustotal.com/api/v3/files/{id}/comments`

##### cURL
```curl
curl --request POST \
  --url https://www.virustotal.com/api/v3/files/{id}/votes \
  --header 'x-apikey: <your API key>' \
  --data '{"data": {"type": "vote", "attributes": {"verdict": "malicious"}}}''
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}/votes"
headers = {"x-apikey" : "<ключ доступа к API>"}
votes = {"data": {"type": "vote", "attributes": {"verdict": "malicious"}}}
response = requests.post(api_url, headers=headers, json=votes)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **data** - голос (json).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

С помощью этой функции вы можете опубликовать свой голос за данный файл. Тело для запроса POST должно быть JSON-представлением объекта голосования. Обратите внимание, однако, что вам не нужно указывать идентификатор объекта, так как они автоматически генерируются для новых голосов.

Атрибут `verdict` должен быть либо `harmless`, либо `malicious`.

##### Пример ответа
```
{
  "data": {
    "type": "vote",
    "attributes": {
    	"verdict": "harmless"
    }
  }
}
```

### <a name="get_download_url"> ![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/download_url </a>

Получение URL для загрузки файла.

>##### :warning: Требуются особые привилегии
>
>Эта функция доступна только для пользователей со специальными привилегиями.

**GET** `https://www.virustotal.com/api/v3/files/id/download_url`

##### cURL
```curl
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{id}/download_url \
  --header 'x-apikey: <your API key>'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}/download_url"
headers = {"x-apikey" : "<ключ доступа к API>"}
response = requests.get(api_url, headers=headers)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Эта функция возвращает подписанный URL, с которого можно загрузить указанный файл. Получение URL считается загрузкой файла в квоте, даже если вы на самом деле не загружаете файл. URL можно использовать для загрузки файла несколько раз, не потребляя никакой квоты. Срок действия URL истекает через 1 час.

##### Пример ответа
```
{
  "data": "https://vtsamples.commondatastorage.googleapis.com/275a..fd0f?GoogleAccessId=758681729565-rc7fcckv235v1@developer.gserviceaccount.com&Expires=1524733537&Signature=GRs9WLy...oHA%3D"
}
```

### <a name="get_download"> ![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/download </a>

Загрузка файла.

>##### :warning: Требуются особые привилегии
>
>Эта функция доступна только для пользователей со специальными привилегиями.

##### cURL
```curl
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{id}/download \
  --header 'x-apikey: <your API key>'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}/download"
headers = {"x-apikey" : "<ключ доступа к API>"}
response = requests.get(api_url, headers=headers)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Эта функция похожа на [GET /files/{id}/download_url](#get_download_ur), но она перенаправляет вас на URL загрузки файла. URL загрузки, на который вы перенаправлены, может быть использован повторно столько раз, сколько вы хотите в течение 1 часа. После этого срока действие URL истекает и он больше не может быть использован.

### <a name="get_files_relationship"> ![](https://i.imgur.com/CBcN0Fh.png) /files/{id}/{relationship} </a>

Получение объектов, связанных с файлом.

**GET:** `https://www.virustotal.com/api/v3/files/{id}/{relationship}`

##### cURL
```curl
curl --request GET \
  --url https://www.virustotal.com/api/v3/files/{id}/{relationship} \
  --header 'x-apikey: <your API key>'
```

##### Python
```python
import requests
    ...
api_url = "https://www.virustotal.com/api/v3/files/{id}/{relationship}"
headers = {"x-apikey" : "<ключ доступа к API>"}
query = {"limit": "<limit)>", "cursor": "<cursor>"}
response = requests.get(api_url, headers=headers)
```

##### Параметры запроса

- **id** - SHA-256, SHA-1 или MD5 идентификатор файла (string);
- **relationship** - наименование отношения (см. таблицу ниже);
- **limit** - максимальное число комментариев в ответе (int_32, необязательный параметр);
- **cursor** - курсор продолжения (string, необязательный параметр).

##### Заголовок запроса

- **x-apikey** - ключ доступа к API (string).

Объекты типа `file` имеют ряд отношений с другими файлами и объектами. Как уже упоминалось в разделе "[Отношения](#relationships)", эти связанные объекты можно получить, отправив GET-запросы на URL, соответствующий нужному отношению.

Некоторые отношения доступны только тем пользователям, которые имеют доступ к VirusTotal Intelligence.

##### Отношения, поддерживаемые объектами файла:

Отношения | Описание | Доступность
----------|----------|------------
`analyses` | Объект `analyses` для файла | Только для пользователей `intelligence`
`behaviours` | Отчеты о поведении для файла. См. "[Поведение файлов (file behaviour)](#file_behaviour)" | Все пользователи
`bundled_files` | Файлы, собранные в одном файле. | Все пользователи
`carbonblack_children` | Файлы, полученные из файла Carbon Black | Только для пользователей `intelligence`
`carbonblack_parents` | Файлы Carbon Black, из которых был получен файл | Только для пользователей `intelligence`
`comments` | Комментарии к файлу | Все пользователи
`compressed_parents` | Сжатые файлы, содержащие этот файл | Все пользователи
`contacted_domains` | Домены, с которыми связан файл | Все пользователи
`contacted_ips` | IP-адреса, с которыми связан файл | Все пользователи
`contacted_urls` | URL, с которыми связан файл | Все пользователи
`email_parents` | Файлы электронной почты, содержащие этот файл | Только для пользователей `intelligence`
`embedded_domains` | Имена доменов, содержащиеся в файле | Только для пользователей `intelligence`
`embedded_ips` | IP-адреса, содержащиеся в файле | Только для пользователей `intelligence`
`execution_parents` | Файлы, которые запустили файл | Все пользователи
`graphs` | Графики, включающие файл | Все пользователи
`itw_urls` | URL "in the wild", откуда был загружен файл | Все пользователи
`overlay_parents` | Файлы, содержащие файл в виде оверлея | Все пользователи
`pcap_parents` | Файлы PCAP, содержащие этот файл | Все пользователи
`pe_resource_parents` | PE-файлы, содержащие файл в качестве ресурса | Все пользователи
`similar_files` | Файлы, похожие на данный файл | Только для пользователей `intelligence`
`submissions` | Представления файла | Только для пользователей `intelligence`
`screenshots` | Скриншоты, связанные с песочницей, в которой выполнялся файла | Все пользователи
`votes` | Результаты голосования для файла | Все пользователи




