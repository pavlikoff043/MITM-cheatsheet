# MITM-cheatsheet
Мы постарались собрать воедино все известные MITM-атаки и методы защиты от них. Здесь также представлены инструменты для проведения MITM-атак, некоторые интересные случаи атак и связанные с ними хитрости.

**Note:**  Примечание: Практически все описанные здесь инструменты атаки не имеют внутри себя сниффера. Они обеспечивают только атаку. Инструменты для сниффинга здесь: [Data sniffing](#data-sniffing). 

Шпаргалка для пентестеров и команд защиты об атаках типа Man In The Middle.
## Table of Contents  
* [L2](#l2)  
	* [Arp spoofing](#arp-spoofing)
	* [STP(RSTP, PVSTP, MSTP) spoofing](#stprstp-pvstp-mstp-spoofing)   
	* [NDP spoofing](#ndp-spoofing) :hourglass_flowing_sand:  
	* [VLAN hopping](#vlan-hopping)  
* [L3](#l3)  
	* [SLAAC Attack](#slaac-attack)  
	* [Hijacking HSRP (VRRP, CARP)](#hijacking-hsrp-vrrp-carp) :hourglass_flowing_sand:  
	* [Dynamic routing protocol spoofing (BGP)](#dynamic-routing-protocol-spoofing-bgp) :hourglass_flowing_sand:  
	* [RIPv2 Routing Table Poisoning](#ripv2-routing-table-poisoning)  
	* [OSPF Routing Table Poisoning](#ospf-routing-table-poisoning) :hourglass_flowing_sand:  
	* [EIGRP Routing Table Poisoning](#eigrp-routing-table-poisoning)  
	* [ICMP Redirect](#icmp-redirect)  
* [L4+](#l4)  
	* [NetBIOS (LLMNR) spoofing](#netbios-llmnr-spoofing)  
	* [DHCP spoofing](#dhcp-spoofing)  
	* [Rogue DHCP (DHCPv6)](#rogue-dhcp-dhcpv6)  
* [Wireless](#wireless)  
	* [Karma attacks (Wi-Fi)](#karma-attacks-wi-fi)  
	* [Rogue BTS (GSM)](#karma-attacks-wi-fi) :hourglass_flowing_sand:  
* [Attack technics](#attack-technics) :hourglass_flowing_sand:  
	* [Data sniffing](#data-sniffing) :hourglass_flowing_sand:  
	* [Injections in data](#injections-in-data) :hourglass_flowing_sand:  
		* [Malicious JS in HTML](#malicious-js-in-html) :hourglass_flowing_sand:  
		* [HTA](#hta) :hourglass_flowing_sand:  
	* [Data modification](#data-modification) :hourglass_flowing_sand:  
		* [Wsus](#wsus) :hourglass_flowing_sand:  
		* [DNS hijacking](#dns-hijacking) :hourglass_flowing_sand:  
* [Hacker notes](#hacker-notes)   
	* [Difference between CPU (or why most of that attack imposible from your notebook)](#difference-between-cpu-or-why-most-of-that-attack-imposible-from-your-notebook) 
* [SSLStrip, SSLStrip+, HSTS](#sslstrip-sslstrip-hsts) 

:hourglass_flowing_sand: - part in process

## L2

### Arp spoofing
**Сomplexity:** Low  
**Relevance:** High  
**Description:**  
Протокол разрешения адресов (ARP) предназначен для преобразования IP-адресов в MAC-адреса. Все сетевые устройства, которым необходимо взаимодействовать в сети, используют широковещательные ARP-запросы для выяснения MAC-адресов других машин.
  
Почти все средства arp-спуфинга используют [gratuitous](http://wiki.wireshark.org/Gratuitous_ARP) arp-ответ. Беспричинный ARP-ответ - это ответ на отсутствие ARP-запроса.

Несмотря на эффективность беспричинного ARP, он особенно небезопасен, поскольку с его помощью можно уверить удаленный хост в том, что MAC-адрес системы в той же сети изменился, и указать, какой адрес используется сейчас.

<details>
<summary>Типичный пример атаки arp spoofing</summary>

1. Перед проведением ARP-спуфинга в ARP-таблицах узлов A и B имеются записи с IP - и MAC-адресами друг друга. Информация передается между узлами A и B.

2. В процессе ARP-спуфинга компьютер С, осуществляющий атаку, посылает ARP-ответы (без получения запросов = gratuitous arp) => 
* узлу A: с IP-адресом узла B и MAC-адресом узла C; 
узлу B: с IP-адресом узла A и MAC-адресом узла C.

3. Поскольку компьютеры поддерживают безвозмездный ARP, они модифицируют свои собственные ARP-таблицы и помещают в них записи, в которых вместо реальных MAC-адресов компьютеров A и B указан MAC-адрес компьютера C.
</details>

Также существует вероятность успешной атаки и другим способом. Когда вы будете наблюдать за arp-активностью в сегменте сети и вдруг заметите arp-запрос жертвы, вы можете попробовать отправить arp-ответ жертве быстрее, чем адресат этого запроса. Некоторые производители могут принять этот прием. 

**Средства атаки:**
* [`bettercap`](https://www.bettercap.org/legacy/)` -T 10.10.10.10 -X --httpd --proxy-https --proxy`  
Старая версия инструмента проще, но и в ней есть [new](https://github.com/bettercap/bettercap) модный, написанный на языке Go.
**Note:** Bettercap have excelent sniffer inside.
* [`arpspoof`](http://github.com/smikims/arpspoof)` -i eth0 -t 10.10.10.10`
* [Intercepter-NG](http://sniff.su/) (Now it could be installed at Linux) 

**Обнаружение атак**

* [arpwatch](https://ee.lbl.gov)  
Программа отслеживает всю ARP-активность на выбранных интерфейсах. Если программа замечает аномалии, например, изменение MAC-адреса при сохранении IP-адреса или наоборот, она сообщает об этом в syslog.
* [XArp](http://www.chrismc.de/)  
Arpwatch for Windows
* [remarp](http://www.raccoon.kiev.ua/projects/remarp/)
Arpwatch via SNMP


**Предотвращение атак**

* Ручные ARP-таблицы   
Она имеет ограничения, так как вызывает трудности с масштабируемостью сети. А для беспроводной сети это является сложной задачей, практически невозможной.

* Patching  
Такие утилиты, как Anticap и Antidote, играют важную роль в предотвращении ARP-спуфинга. Anticap предотвращает обновление ARP-кэша с различными MAC-адресами по сравнению с существующим ARP-кэшем, что действительно предотвращает ARP-спуфинг, но при этом нарушается спецификация протокола ARP, что действительно является проблемой, а Antidote предотвращает ARP-отравление несколько другим способом. Он анализирует вновь полученный ARP-ответ с существующим кэшем. Если новый кэш отличается от предыдущего, то он ищет MAC-адрес, если тот еще жив. Если MAC-адрес из предыдущего кэша жив, то он отвергает новый и добавляет MAC-адрес злоумышленника в список запрещенных MAC-адресов для предотвращения дальнейших попыток ARP-травления на том же целевом компьютере.

* Создание VLAN на коммутаторе  
На коммутаторе создается VLAN, содержащая только сам коммутатор и конкретное сетевое устройство.

* Создание зашифрованных соединений  
Этот метод также подходит для публичных сетей, поскольку весь трафик шифруется и перехватить данные пользователя невозможно.

* DAI  
Динамическая проверка ARP в системах cisco позволяет предотвратить атаки типа "человек посередине", не передавая недопустимые или необоснованные ARP-ответы на другие порты в той же VLAN. Динамическая ARP-инспекция перехватывает все ARP-запросы и все ответы на недоверенных портах. Каждый перехваченный пакет проверяется на наличие корректной привязки IP-адреса к MAC-адресу с помощью DHCP snooping. Отклоненные ARP-пакеты либо отбрасываются, либо регистрируются коммутатором для аудита, что позволяет пресекать атаки ARP poisoning. Входящие ARP-пакеты на доверенных портах не проверяются. 

> Related links  
[How ARP works](https://www.tummy.com/articles/networking-basics-how-arp-works/)

### STP(RSTP, PVSTP, MSTP) spoofing
**Сложность:** Высокая  
**Актуальность:** Умеренная  
**Описание:**  
Протокол STP (spanning tree) предназначен для обнаружения и предотвращения петель в сети при наличии избыточных путей между коммутаторами.

Тот, кто сможет эмулировать устройство с (более низким) идентификатором корневого коммутатора (подключив новое виртуальное устройство с более низким приоритетом или используя инструмент генерации пакетов STP), может частично или полностью перехватить трафик виртуальной сети. Как правило, у злоумышленника нет физического соединения с двумя коммутаторами, поэтому описанный метод атаки вряд ли возможен. Однако в беспроводных сетях ситуация меняется, поскольку кабельное соединение (розетка в офисе) и беспроводное соединение (точка доступа) могут заканчиваться на разных коммутаторах.

**Инструменты нападения**
Внимание: Часто данный тип атаки приводит к отказу в обслуживании.

* [`yersinia`](https://github.com/tomac/yersinia)` –G`
Yersinia имеет графический интерфейс и интерактивную консоль, необходимо выбрать сетевые интерфейсы и запустить MITM-атаку.
Графический интерфейс работает нестабильно, поэтому можно воспользоваться интерактивным интерфейсом: `yersinia –I`.
* [`ettercap`](http://ettercap.github.lo/ettercap/downloads.html)  
Еще один инструмент для Linux. Необходимо выбрать интерфейсы, затем нажать на плагин "stp mangier" и запустить его.

**Техника защиты**  
* Отключение STP на портах доступа (для прекращения приема BDPU от пользователей), включение защиты портов на всех пользовательских портах, а также ограничение физического доступа к сетевому оборудованию.
* [configuration tools](https://community.cisco.com/t5/networking-documents/spanning-tree-protection/ta-p/3116493) that protect STP (Cisco).

### NDP spoofing Подмена ПНР
**Сложность:** Умеренная  
**Актуальность:** Близко к нулю  
**Описание:**  
**Средства атаки**  
**Техника защиты**  

### VLAN hopping
**Сложность:** Умеренная  
**Актуальность:** Нет  
**Описание:**  
Виртуальная локальная сеть (LAN) - это логическая подсеть, объединяющая устройства из разных физических локальных сетей. В крупных бизнескомпьютерных сетях часто создаются виртуальные локальные сети для переразделения сети с целью улучшения управления трафиком.

[VLANs](https://en.wikipedia.org/wiki/Virtual_LAN) работают путем наложения меток на сетевые кадры и обработки этих меток в сетевых системах, создавая видимость и функциональность сетевого трафика, который физически находится в одной сети, но ведет себя так, как будто он разделен между отдельными сетями. 

VLAN hopping - это общее название атак, предполагающих доступ к VLAN, которая изначально (до атаки) была недоступна злоумышленнику.

<details>
<summary>Она может быть выполнена двумя способами: </summary>

1. Основная атака VLAN Hopping (с использованием [DTP](https://en.wikipedia.org/wiki/Dynamic_Trunking_Protocol))  
Работает только на старых коммутаторах Cisco.  
Злоумышленник выступает в роли коммутатора, чтобы обманом заставить легитимный коммутатор создать между ними транкинговое соединение. По транковому каналу могут проходить пакеты из любой VLAN. После создания магистрального канала злоумышленник получает доступ к трафику любой VLAN. Данный метод является успешным только в том случае, если легитимный коммутатор настроен на согласование транка. Это происходит, когда интерфейс сконфигурирован в режиме "dynamic desirable", "dynamic auto" или "trunk". Если на целевом коммутаторе настроен один из этих режимов, злоумышленник может сгенерировать DTP-сообщение со своего компьютера и создать магистральный канал.

2. Атака *Двойная метка* происходит, когда злоумышленник добавляет и изменяет метки в кадре Ethernet, позволяя пересылать пакеты через любую VLAN. Эта атака использует преимущества обработки меток многими коммутаторами. Большинство коммутаторов удаляют только внешнюю метку и пересылают кадр на все порты собственной VLAN. При этом данный метод будет успешным только в том случае, если атакующий принадлежит к "родной" VLAN магистрального канала. Еще один важный момент: данная атака является строго односторонней, поскольку невозможно инкапсулировать обратный пакет. </details>

[The Exploit-db doc](https://www.exploit-db.com/docs/english/45050-vlan-hopping-attack.pdf)  
[The Guide with illustrations and video](https://networklessons.com/cisco/ccnp-switch/vlan-hopping)  
[VLAN hopping full guide](https://www.alienvault.com/blogs/security-essentials/vlan-hopping-and-mitigation)  
[In-depth article](https://learningnetwork.cisco.com/blogs/vip-perspectives/2019/07/12/vlan1-and-vlan-hopping-attack)  


**Средства атаки**

* [`yersinia`](https://github.com/tomac/yersinia)` –G`
Yersinia имеет графический интерфейс и интерактивную консоль, в которой необходимо выбрать сетевые интерфейсы и запустить MITM-атаку.  
Графический интерфейс работает нестабильно, поэтому можно воспользоваться интерактивным интерфейсом: `yersinia –I`. 

* [Scapy](https://scapy.net/)  
Scapy - это программа на языке Python, позволяющая пересылать, обнюхивать, вскрывать и подделывать сетевые пакеты. С ее помощью можно создавать специально созданные кадры, необходимые для обработки данной атаки.

* [`dtp-spoof.py`](https://github.com/fleetcaptain/dtp-spoof)` -i eth0` sends a DTP Trunk packet out eth0 using eth0's mac address
DTP-spoof - это инструмент безопасности для проверки конфигурации протокола Dynamic Trunking Protocol (DTP) коммутаторов. Если целевой коммутатор настроен на согласование режима работы порта, то потенциально можно перевести порт целевого коммутатора в режим Trunk, получив таким образом доступ к дополнительным VLAN.

**Техника защиты**

1. Основная атака VLAN Hopping (с использованием DTP).  
Она может быть выполнена только в том случае, если интерфейсы настроены на согласование транка. Чтобы предотвратить использование VLAN hopping, можно предпринять следующие меры:  
	+ Убедитесь, что порты не настроены на автоматическое согласование транков, отключив DTP.
	+ Не настраивайте точки доступа в одном из следующих режимов: "dynamic desirable", "dynamic auto" или "trunk".
	+ Отключите все интерфейсы, которые в данный момент не используются.

2. Двойная метка  
Для предотвращения атаки с использованием двойной метки необходимо, чтобы собственные VLAN всех магистральных портов отличались от пользовательских VLAN.


## L3
### SLAAC Attack 

**Сложность:** Низкая  
**Актуальность:** Высокая  
**Описание**

SLAAC - Stateless Address AutoConfiguration. SLAAC является одним из способов конфигурирования сети хоста, подобно DHCPv4. SLAAC предоставляет хосту IPv6 значение префикса, длину префикса и локальный адрес шлюза по умолчанию без участия DHCPv6-сервера, который хранит состояние предоставленных адресов (поэтому он и называется stateless). Процесс SLAAC выполняется при конфигурировании SLAAC-only и SLAAC+DHCPv6 Stateless. 

Основная проблема этого процесса заключается в том, что злоумышленник может подстроить неавторизованный RA так, чтобы передать хостам свою конфигурацию (например, стать маршрутизатором по умолчанию на канале). Все хосты, у которых включен IPv6, потенциально уязвимы для SLAAC-атак. Особенно в тех случаях, когда IPv6 включен в ОС по умолчанию, но организация не развернула IPv6 в каком-либо виде.

Другая угроза в RA исходит от возможности передачи конфигурации DNS по RA, так что злоумышленник может подделать и ее: [RFC 6106 - IPv6 Router Advertisement Options for DNS Configuration](http://tools.ietf.org/html/rfc6106).  

**Attack Tools**  

* [suddensix](https://github.com/Neohapsis/suddensix)  
Это скрипт, который предустанавливает инструменты, используемые исследователем безопасности Алеком Уотерсом в его [post about SLAAC attack](https://resources.infosecinstitute.com/slaac-attack/). Скрипт немного устарел и хорошо работает на Ubuntu 12.04 LTS. Лучше создать для него отдельную виртуальную машину.

* [EvilFOCA](https://github.com/ElevenPaths/EvilFOCA)  
Удивительный инструмент для windows для IPv6 MITM-атак. Инструмент, написанный на C#, с графическим интерфейсом, позволяющий осуществлять IPv6-атаки, включая SLAAC-атаки, поддельные DHCPv6 и даже SLAAC DoS, что означает объявление поддельных маршрутов в нескольких RA на линии связи.

* [THC-IPv6](https://github.com/vanhauser-thc/thc-ipv6)  
Написанный на языке C инструментарий для атак на IPv6, который, помимо многих других возможностей, позволяет осуществлять атаки с использованием RA.
 
**Техника защиты** 
Самый простой способ защиты от SLAAC-атак - просто отключить IPv6 на всех хостах сети. Но это решение подходит только для сетей, в которых стек IPv6 не используется и был включен только из-за неправильной конфигурации.  

<details>
 <summary>Внедрение у вендоров</summary>

Компания Cisco реализовала технологию "IPv6 First Hop Security", которая включена в коммутаторы Catalyst серий 6500, 4500, 3850, 3750 и 2960, маршрутизаторы серии 7600 и контроллеры беспроводных локальных сетей Cisco серии 5700. Реализованы RA Guard, DHCP Guard, а также IPv6 Snooping. Более подробную информацию можно найти [here](https://www.cisco.com/c/dam/en/us/products/collateral/ios-nx-os-software/enterprise-ipv6-solution/aag_c45-707354.pdf).  

Компания Juniper реализовала RA Guard. Есть один странный факт: в утверждении `router-advertisement-guard`  [documentation page](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/router-advertisement-guard-edit-fo.html) упоминается, что поддерживаются только платформы серии EX. Однако на странице [Configuring Stateless IPv6 Router Advertisement Guard](https://www.juniper.net/documentation/en_US/junos/topics/task/configuration/port-security-ra-guard.html) and [Configuring Stateful IPv6 Router Advertisement Guard](https://www.juniper.net/documentation/en_US/junos/topics/task/configuration/port-security-ra-guard-stateful.html) упоминается, что платформы серии EX и некоторые платформы серии QFX поддерживают RA Guard: EX2300(15.1X53-D56), EX2300-VC(15.1X53-D56), EX3400(15.1X53-D55), EX3400-VC(15.1X53-D55), EX4300(16.1R1), EX4300-VC(16. 1R1), EX4300 Multigigabit(18.2R1), EX4600(18.3R1), EX4600-VC(18.3R1) и QFX5100(18.2R1), QFX5110(17.2R1), QFX5200(18.2R1).

Mikrotik, к сожалению, не реализовал подобные технологии. Существует [presentation](https://mum.mikrotik.com/presentations/PL12/maia.pdf) с Mikrotik Users' Meeting и автор посоветовал просто изолировать сегмент сети второго уровня. Других ценных советов найти не удалось. Проблема также была [mentioned](https://forum.mikrotik.com/viewtopic.php?t=68004) на форуме пользователей Mikrotik в 2012 году. 

К сожалению, существуют методы усиления анализа трафика, которые нарушают работоспособность методик защиты (например, скрытие RA в заголовке Hob-By-Hop). Существует  [draft RFC](https://tools.ietf.org/html/draft-gont-v6ops-ra-guard-evasion-01) в котором описывается обход RA Guard. Техника обхода основана на использовании фрагментации пакетов IPv6. Некоторые дополнительные рекомендации по фрагментации представлены в [RFC 6980 - Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery](http://tools.ietf.org/html/rfc6980).  
</details>

<details>
 <summary>10 основных идей для решения проблемы</summary>

[RFC 6104 - Rogue IPv6 Router Advertisement Problem Statement](https://tools.ietf.org/html/rfc6104) представлены 10 основных идей по решению проблемы Rogue RA. Таким образом, приведенный выше раздел является лишь кратким обзором того, что IETF может предложить в качестве решения на сегодняшний день:  

1. *Ручная конфигурация* IPv6-адреса и отключение автоконфигурации для игнорирования RA-сообщений.   
Для Linux-систем значения `net.ipv6.conf.*` могут быть изменены:  
	```
    net.ipv6.conf.all.autoconf = 0  
	net.ipv6.conf.all.accept_ra = 0  
	net.ipv6.conf.default.accept_ra=0  
	net.ipv6.conf.all.accept_ra=0  
	net.ipv6.conf.eth0.accept_ra=0 
    ```
	For Mac-OS there is a [guide for IPv6 hardening](http://www.ipv6now.com.au/primers/ERNW_Hardening_IPv6_MacOS-X_v1_0.pdf). Однако автор столкнулся с проблемой, связанной с параметром, отвечающим за прием RA в Mac-OS: net.inet6.ip6.accept_rtadv должен быть установлен в 0, но это невозможно. В исходном коде ядра он назван deprecated и определен как read-only, но Mac-OS продолжает принимать RA. Таким образом, в Mac-OS невозможно отключить RA через sysctl. Единственное, что можно сделать, это установить максимальное число допустимых префиксов и максимальное число допустимых маршрутизаторов по умолчанию равным 1.  

	Для Windows существует команда, которую можно выполнить под администратором, чтобы отключить автоконфигурацию:
	```
	netsh interface ipv6 set interface "Local Area Connection" routerdiscovery=disabled  
	```

2. *RA Snooping* в коммутаторах L2 аналогично DHCP snooping, чтобы RA из неправильных источников могли быть отброшены.  

3. *ACL на управляемых коммутаторах* можно использовать, если на коммутаторе существует механизм ACL, который может блокировать исходящие ICMPv6 RA на пользовательских портах (используемых для доступа пользователей к локальной сети). Таким образом, если такой ACL можно реализовать на используемой платформе, то ни один пользователь в локальной сети не сможет транслировать/уникально передавать RA.  

4. *SEcure Neighbor Discovery - SEND* - [RFC 3971](https://tools.ietf.org/html/rfc3971) это протокол, который предлагает использовать криптографию с открытым ключом для защиты связи между маршрутизатором и хостами.  

5. *Router Preference Option* - этот метод применим только в случае случайных RA от пользователей. Идея заключается в том, что администратор может установить "высокий" уровень предпочтения во всех легитимных RA, чтобы узлы IPv6 не перезаписывали конфигурацию, полученную такими RA, если они имеют "средний" или "низкий" уровень предпочтения. Опция Router Preference Option присутствует в [RFC 4191 - Default Router Preferences and More-Specific Routes](https://tools.ietf.org/html/rfc4191).  

6. *Rely on Layer 2 Admission Control* - идея основана на том, чтобы полагаться на развертывание 802.1x, чтобы злоумышленники не смогли присоединиться к локальной сети для отправки RA и проведения атаки.  

7. *Использование пакетных фильтров на базе хоста* - при наличии возможности передачи конфигурации на машины пользователей пакетные фильтры на базе хоста могут быть настроены на прием RA только с точных IPv6-адресов.  

8. *Использование "интеллектуального" средства деприватизации* - идея состоит в том, чтобы наблюдать за трафиком канала связи на предмет наличия неавторизованных RA и деприватизировать их для хостов путем отправки деприватизирующего RA с адресом неавторизованного маршрутизатора в нем и полем времени жизни маршрутизатора, установленным в 0. Атаковать трафик атаки.  

9. *Использование Layer 2 Partitioning* - идея заключается в том, что если каждый пользователь или система будут разделены на различные среды Layer 2, то влияние некоторых неавторизованных RA может быть ограничено. Этот метод приводит к росту затрат на программное и аппаратное обеспечение.  

10. *Добавление опций шлюза/префикса по умолчанию в DHCPv6* - оставление автоконфигурации SLAAC для автоконфигурации DHCPv6 частично решает проблему шлюзов и префиксов по умолчанию, посылаемых неавторизованными RA, но также приводит к проблемам с неавторизованными серверами DHCPv6. Вторая проблема заключается в том, что RA по-прежнему используется для информирования хостов об использовании DHCPv6.  

The [4th section of RFC 6104](https://tools.ietf.org/html/rfc6104#section-4) имеется таблица, содержащая способы смягчения пригодности для двух случаев Rogue RA: ошибка администратора и ошибка пользователя.
</details>

**Сопутствующие средства мониторинга**.  
Существует ряд инструментов, которые могут быть полезны для обнаружения и мониторинга неавторизованных РА:

* [NDPMon](http://ndpmon.sourceforge.net/)   
Позволяет выбрать следующие опции конфигурации перед компиляцией:  

	`--enable-mac-resolv`  
	  Determine the vendor by OUI in MAC-address.  
	`--enable-countermeasures`  
	  Functionality of response to attacks (no described to which ones and how).  
	`--enable-syslogfilter`  
	  Save syslog to /var/log/ndpmon.lo .  
	`--enable-lnfq`  
	  Use libnetfilter_queue instead of PCAP (have some requirements to be installed and ip6tables rules).  
	`--enable-webinterface`  
	  Post html reports (some web server required as nginx/apache).  

* [Ramond](http://ramond.sourceforge.net/)  
Позволяет добавить в белый список MAC-адреса определенных легитимных маршрутизаторов, префикс, используемый для 6to4, и неизвестные префиксы. На основе этой конфигурации инструмент осуществляет мониторинг RA-трафика с целью поиска неавторизованных маршрутизаторов.

* [6MoN](https://www.6monplus.it/)  
Позволяет контролировать состояние сети, наблюдать за процессом DAD и сообщениями NS. DAD означает Duplicate Address Discovery и определяет наличие конфликта дублирования адресов в сети. NS означает Neighbor Solicitation (ICMPv6 тип 135) и используется для определения соседа по каналу связи.

> Related RFCs   
[RFC 6104 - Rogue IPv6 Router Advertisement Problem Statement](https://tools.ietf.org/html/rfc6104)  
[RFC 6105 - IPv6 Router Advertisement Guard](https://tools.ietf.org/html/rfc6105)  
[RFC 3736 - Stateless Dynamic Host Configuration Protocol (DHCP) Service for IPv6](https://tools.ietf.org/html/rfc3736)  
[RFC 4862 - IPv6 Stateless Address Autoconfiguration (SLAAC)](https://tools.ietf.org/html/rfc4862)  
[RFC 7113 - Implementation Advice for IPv6 Router Advertisement Guard (RA-Guard)](https://tools.ietf.org/html/rfc7113)  
[RFC 8021 - Generation of IPv6 Atomic Fragments Considered Harmful](https://tools.ietf.org/html/rfc8021)  

> Other useful related links  
[Windows machines compromised by default configuration flaw in IPv6](https://resources.infosecinstitute.com/slaac-attack/)  
[Why You Must Use ICMPv6 Router Advertisements](https://community.infoblox.com/t5/IPv6-CoE-Blog/Why-You-Must-Use-ICMPv6-Router-Advertisements-RAs/ba-p/3416)  

### Перехват HSRP (VRRP, CARP)
**Сложность:** Высокая  
**Актуальность:** Высокая  
**Описание:**  
**Инструменты атаки**.
Scapy - самый простой способ создания PoC и перехвата статуса активного узла:

For HSRP:
```python
#!/usr/bin/env python
from scapy.all import *

if __name__ == "__main__":
    ip = IP(src="10.0.0.100", dst="224.0.0.2")
    udp = UDP(sport=1985, dport=1985)
    hsrp = HSRP(group=1, priority=150, virtualIP="10.0.0.1", auth="cisco")
    send(ip/udp/hsrp, iface="eth1", inter=3, loop=1)
```

For VRRP:
```python
#!/usr/bin/env python
from scapy.all import *

if __name__ == "__main__":
    ip = IP(src="10.0.0.100", dst="224.0.0.2")
    udp = UDP()
    vrrp = VRRP(vrid=1, priority=150, addrlist=["10.0.0.7", "10.0.0.8"], ipcount=2, auth1='cisco')
    send(ip/udp/vrrp, iface="eth1", inter=3, loop=1)
```
**Техника защиты**  

### Подмена протокола динамической маршрутизации (BGP)
**Сложность:** Высокая  
**Актуальность:** Высокая  
**Условия:**  
**Описание:**  
**Инструменты атаки** 
https://github.com/fredericopissarra/t50  
**Defence technics**  

### Отравление таблицы маршрутизации RIPv2
**Сложность:** Средняя  
**Актуальность:** Средняя  
**Условия:**  
RIP реализован;  
Используется RIPv1;  
аутентификация RIPv2 отключена.  
**Описание:**  
Существует 3 версии RIP:
* *RIPv1*: первая версия, описанная в [RFC 1058](https://tools.ietf.org/html/rfc1058);
* *RIPv2*: усовершенствованный в основном за счет добавления версии механизма аутентификации, описанной в [RFC 2453](https://tools.ietf.org/html/rfc2453);
* *RIPv3* or *RIPng* (next generation): поддерживает протокол IPv6, описанный в [RFC 2080](https://tools.ietf.org/html/rfc2080).  

Наиболее широко реализованный протокол - RIPv2. RIPv1 вообще не является безопасным, поскольку не поддерживает аутентификацию сообщений. Существует хороший [write up](https://digi.ninja/blog/rip_v1.php) по эксплуатации RIPv1 путем инъекции фальшивого маршрута.  

Как указано в RFC 2453, маршрутизатор RIPv2 должен обмениваться информацией о маршрутизации каждые 30 секунд. Суть атаки заключается в отправке поддельных сообщений RIP Response, содержащих маршрут, который злоумышленнику необходимо внедрить. Хотя для маршрутизаторов RIPv2 существует специальная многоадресная рассылка - 224.0.0.9, ответы, посланные как одноадресные, также могут быть приняты. Это, например, может затруднить обнаружение атаки, по сравнению со случаем распространения многоадресной поддельной маршрутизации. Существует хорошая короткая статья [write up](https://microlab.red/2018/04/06/practical-routing-attacks-1-3-rip/) о взломе RIPv2-сети без RIPv2-аутентификации на примере использования Scapy.  

**Атакующие инструменты**  
* [t50](https://gitlab.com/fredericopissarra/t50) - многопротокольный инструмент для инжекции трафика и тестирования на проникновение в сеть. Среди многих других протоколов поддерживает RIP.
  
**Техника защиты**.  
Если маршрутизатор не настроен на аутентификацию сообщений RIPv2, он будет принимать неаутентифицированные сообщения RIPv1 и RIPv2. Наиболее безопасной конфигурацией в этом случае является настройка аутентификации RIPv2 таким образом, чтобы маршрутизатор не принимал неаутентифицированные сообщения RIPv1 и v2 и тем самым лишал неаутентифицированный маршрутизатор возможности проложить маршрут. Этот механизм описан в [RFC 2082 - RIP-2 MD5 Authentication](https://tools.ietf.org/html/rfc2082), но там описано использование MD5, которая признана слабой функцией хеширования. Более совершенный вариант, подразумевающий использование SHA-1, описан в [RFC 4822 - RIPv2 Cryptographic Authentication](https://tools.ietf.org/html/rfc4822).  

К сожалению, RIPv2 поддерживает только Plain-text и MD5 Authentication. Первая бесполезна в случае сниффинга сети, MD5-аутентификация лучше в случае пассивного злоумышленника, перехватывающего пакеты, так как не передает пароль открытым текстом.  
В руководстве [The Configuration of RIPv2 Authentication guide](https://www.cisco.com/c/en/us/support/docs/ip/routing-information-protocol-rip/13719-50.html#md5) описано, как установить эту функцию на устройствах *Cisco*.  
Руководство по настройке MD5-аутентификации для *Mikrotik* присутствует [здесь](https://mikrotik.com/documentation/manual_2.6/Routing/RIP.html).
Руководство по настройке MD5-аутентификации на устройствах *Juniper* находится [здесь](https://www.juniper.net/documentation/en_US/junos/topics/topic-map/rip-authentication.html).

Также на интерфейсах доступа, которые связываются с конечными устройствами, должна использоваться функция `passive-interface`.  
[Документация Mikrotik](https://wiki.mikrotik.com/wiki/Manual:Routing/RIP#Interface) по настройке функции `passive interface`.  
[Документация Cisco](https://networklessons.com/cisco/ccna-routing-switching-icnd1-100-105/rip-passive-interface) по настройке функции `пассивный интерфейс`.  
[Документация Juniper](https://www.juniper.net/documentation/en_US/junose15.1/topics/reference/command-summary/passive-interface.html) о настройке функции `passive-interface`.  

**Связанные RFC:**.  
[RFC 1388 - RIP Version 2 Carrying Additional Information](https://tools.ietf.org/html/rfc1388)  
[RFC 4822 - RIPv2 Cryptographic Authentication](https://tools.ietf.org/html/rfc4822)  
[RFC 2453 - RIP Version 2](https://tools.ietf.org/html/rfc2453)  
[RFC 2080 - RIPng for IPv6](https://tools.ietf.org/html/rfc2080).  

### Отравление таблиц маршрутизации OSPF
**Сложность:** Высокая  
**Актуальность:** Высокая  
**Условия:**  
**Описание:**  
**Средства атаки**  
**Техника защиты**  

### Отравление таблиц маршрутизации EIGRP
**Сложность:** Средняя  
**Актуальность:** средняя  
**Условия:** В сети реализован протокол EIGRP; аутентификация сообщений EIGRP не установлена  
**Описание:**  
EIGRP расшифровывается как Enhanced Interior Gateway Routing Protocol. Это собственный протокол маршрутизации Cisco с вектором расстояния, основанный на алгоритме Diffused Update Algorithm - DUAL. Основное назначение этого протокола - динамическое обновление таблицы маршрутизации и распространение маршрутов на другие маршрутизаторы.  
Основная проблема безопасности возможна в случае подмены данных в сообщении *Update*, например, для вставки нелегитимного маршрута. В этом случае в таблицу маршрутизации маршрутизатора вносятся изменения, заставляющие его пропускать трафик через устройство, контролируемое злоумышленником, и таким образом налицо MitM-атака.  

**Инструменты атаки**  
* [Eigrp Tools](http://www.hackingciscoexposed.com/?link=tools)  
Скрипт на языке perl, позволяющий создавать пакеты EIGRP и рассылать их по сети. Он даже позволяет установить метрики K1-K4, все флаги и поля EIGRP-пакета. Для работы скрипта требуется установка пакетов `libnet-rawip-perl` и `libnetpacket-perl`. Некоторые примеры использования:  

	`./eigrp.pl --sniff --iface eth0`.  
	  выполнить снифф на интерфейсе eth0  
	`./eigrp.pl --file2ip update.dat --source 192.168.7.8`.  
	  воспроизвести трафик из файла  
	`./eigrp.pl --update --external --as 65534 --source 192.168.7.8`.  
	  отправить и обновить сообщение  

* [EIGRP Security Tool](https://sourceforge.net/projects/eigrpsectool/)  
Скрипт на языке python, позволяющий создавать и отправлять различные пакеты EIGRP. Проблема заключается в том, что попытки запустить скрипт не увенчались успехом из-за отсутствия модуля scapy_eigrp, который не был найден. Также авторы не написали никакой документации к инструменту даже в 
[описание исследования](https://docs.google.com/document/d/1ZVNwi5KRkbY_PxMoODTvwSh3qpzdqiRM9Q4qppP2DvE/edit).

* [t50](https://gitlab.com/fredericopissarra/t50) - многопротокольный инструмент для инжекции трафика и тестирования на проникновение в сеть. Среди многих других протоколов поддерживает манипулирование трафиком EIGRP.

**Технологии защиты**.  
Для защиты сети от распространения недоверенных маршрутов в EIGRP предусмотрен механизм аутентификации обновлений маршрутизаторов. Он использует дайджест с ключом MD5 для подписи каждого пакета, чтобы предотвратить отправку обновлений в сеть неавторизованными устройствами. Это защищает легитимные маршрутизаторы от нелегитимных обновлений и от подмены маршрутизаторов. Ключ представляет собой определенную строку, которая должна быть установлена на других устройствах, считающихся легитимными. Подробное руководство по настройке MD5-аутентификации EIGRP можно найти [здесь] (https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/82110-eigrp-authentication.html#maintask1).  

К сожалению, MD5 признан слабым алгоритмом хеширования из-за коллизий хешей. Устройства Cisco также поддерживают аутентификацию обновлений EIGRP по алгоритму `hmac-sha-256`. Атака на хэш-коллизию для SHA-256 гораздо сложнее, чем для MD5. Руководство по аутентификации EIGRP HMAC-SHA-256 можно найти [здесь] (https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/configuration/15-mt/ire-15-mt-book/ire-sha-256.pdf).  

Область маршрутизации stub EIGRP может быть настроена таким образом, чтобы определить, какие типы маршрутов должен получать запросы маршрутизатор stub, а какие нет. Более подробную информацию о маршрутизации заглушек EIGRP можно найти [здесь](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/configuration/15-mt/ire-15-mt-book/ire-eigrp-stub-rtg.html).  

Другой оптимальной практикой для снижения нежелательного трафика в сети является настройка пассивных интерфейсов. Функция `passive-interface` должна быть установлена на интерфейсах доступа, которые общаются не с сетевыми устройствами, а с конечными устройствами. Инструкция по установке `пассивного интерфейса` на EIGRP и объяснение принципов его работы приведены на [странице документации Cisco](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/13675-16.html).  

### ICMP Redirect
**Сложность:** Средняя  
**Релевантность:** Средняя  
**Описание:**  
Одним из назначений протокола ICMP является динамическое изменение таблицы маршрутизации конечных сетевых систем.
Динамическая маршрутизация удаленного управления изначально была задумана для предотвращения возможной отправки сообщения по неоптимальному маршруту, а также для повышения отказоустойчивости Сети в целом. Предполагалось, что сегмент сети может быть подключен к Интернету через несколько маршрутизаторов (а не через один, как это обычно бывает). В этом случае мы можем обращаться к внешней сети через любой из ближайших маршрутизаторов. Например, к *some_host.site* кратчайший маршрут проходит через "маршрутизатор A", а к *another.site* - через "маршрутизатор B". 

Если один из маршрутизаторов выходит из строя, связь с внешним миром возможна через другой маршрутизатор. 
В качестве "ICMP Redirest атаки" мы изменяем маршрут к некоторому сайту (DNS-имя) в таблице маршрутизации узла A (жертвы) таким образом, чтобы трафик от узла A к некоторому сайту проходил через хакерский ПК

**Условия успеха:**.  
- IP-адрес нового маршрутизатора должен находиться в той же подсети, что и сам атакуемый узел.
- Новый маршрут не может быть добавлен для IP-адреса, находящегося в той же подсети, что и сам узел.
- ОС должна поддерживать и обрабатывать пакеты ICMP redirect. По умолчанию ICMP-переадресация включена в Windows (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect)  
и в некоторых дистрибутивах Linux (cat /proc/sys/net/ipv4/conf/all/accept_redirects)

**Атакующие инструменты**

- [Responder](https://github.com/SpiderLabs/Responder) ([пример](https://github.com/SpiderLabs/Responder/blob/master/tools/Icmp-Redirect.py))
- Hping3 ([пример](https://gist.github.com/githubfoam/91bd46b68c7ee1fe465e9f743a24d140))
- [Mitmf](https://github.com/byt3bl33d3r/MITMf)
- Bettercap ([документация](https://www.bettercap.org/legacy/))

**Техника защиты**

- Отключить icmp-перенаправление ([пример](https://sbmlabs.com/notes/icmp_redirect_attack/))

## L4+

### Подмена NetBIOS (LLMNR)
**Сложность:** Низкая  
**Актуальность:** Высокая  
**Описание:**  
Если клиент windows не может определить имя хоста с помощью DNS, он использует протокол Link-Local Multicast Name Resolution ([LLMNR](https://docs.microsoft.com/en-us/previous-versions//bb878128(v=technet.10))) для опроса соседних компьютеров. LLMNR может использоваться для разрешения адресов IPv4 и IPv6. 

Если это не удается, то используется служба имен NetBios ([NBNS](https://wiki.wireshark.org/NetBIOS/NBNS)). NBNS - это похожий на LLMNR протокол, который служит для тех же целей. Основное различие между ними заключается в том, что NBNS работает только по протоколу IPv4. 

Проблема этой довольно интересной вещи заключается в том, что когда LLMNR или NBNS используются для разрешения запроса, ответить может любой хост в сети, который знает IP хоста, о котором спрашивают. Даже если хост ответит на один из таких запросов с неверной информацией, он все равно будет считаться легитимным.

Злоумышленник может запросить у жертвы NTLM-аутентификацию, в результате чего устройство жертвы отправит NTLM-хэш, который затем может быть использован для атаки методом грубой силы.

<details>
 <summary>Также существует возможность осуществления WPAD-спуфинга.</summary>

Подделку WPAD можно назвать частным случаем LLMNR- и NBNS-подделки. Протокол Web Proxy Auto Discovery используется для автоматического конфигурирования HTTP-прокси-сервера. 

Устройство посылает LLMNR/NBNS-запрос с указанием узла wpad, получает соответствующий IP-адрес и пытается получить доступ к файлу wpad.dat, содержащему информацию о настройках прокси-сервера по протоколу HTTP.

В результате злоумышленник может выполнить подмену LLMNR/NBNS и предоставить жертве собственный файл wpad.dat, в результате чего весь HTTP- и HTTPS-трафик будет проходить через злоумышленника.</details

[Краткое руководство по перехвату учетных данных в открытом виде](https://www.trustedsec.com/2013/07/wpad-man-in-the-middle-clear-text-passwords/)  
[Как работают службы разрешения имен в Microsoft Windows и как ими можно злоупотреблять](https://trelis24.github.io/2018/08/03/Windows-WPAD-Poisoning-Responder/)

**Инструменты атаки**

* [Responder](https://github.com/SpiderLabs/Responder)  
Он может отвечать на запросы LLMNR и NBNS, выдавая свой собственный IP-адрес в качестве адресата для любого запрашиваемого имени хоста. Responder поддерживает отравление WPAD-запросов и передачу корректного PAC-файла wpad.dat.

+ [Mitm6](https://github.com/fox-it/mitm6)  
mitm6 - инструмент для пентестирования, предназначенный для подмены WPAD-запросов и пересылки учетных данных. 

+ [Inveigh](https://github.com/Kevin-Robertson/Inveigh)  
Inveigh - PowerShell ADIDNS/LLMNR/NBNS/mDNS/DNS spoofer и man-in-the-middle tool, предназначенный для помощи тестерам проникновения/красным командам, которые оказались ограничены системой Windows.
	``powershell
	Импорт-модуль .\Inveigh.psd1
	Invoke-Inveigh -NBNS Y -mDNS Y -FileOutput Y -ConsoleOutput Y -SMB Y 
	``` 

+ [Metasploit modules](https://github.com/rapid7/metasploit-framework)  
[auxiliary/spoof/llmnr/llmnr_response](https://www.rapid7.com/db/modules/auxiliary/spoof/llmnr/llmnr_response),  
[auxiliary/spoof/nbns/nbns_response](https://www.rapid7.com/db/modules/auxiliary/spoof/nbns/nbns_response) 

**Техника защиты**

+ Отключите LLMNR и NBNS. Это можно сделать с помощью [GPO](https://en.wikipedia.org/wiki/Group_Policy)  
([как это сделать здесь](http://woshub.com/how-to-disable-netbios-over-tcpip-and-llmnr-using-gpo/))  
+ Создать DNS-запись с именем "WPAD", указывающую на корпоративный прокси-сервер. Таким образом, злоумышленник не сможет манипулировать трафиком.  
+ Отключить "Автоопределение параметров прокси".


### DHCP spoofing 
**Сложность:** Умеренная  
**Актуальность:** Умеренная  
**Описание:**    
Цель данной атаки - *использовать хост или устройство злоумышленника в качестве шлюза по умолчанию* и заставить клиентов использовать ложную службу доменных имен (DNS) и службу имен Windows Internet (WINS-сервер), настроенные злоумышленником. Задача злоумышленника - настроить в сети поддельный DHCP-сервер для предоставления DHCP-адресов клиентам и исчерпать пул IP-адресов других легитимных DHCP-серверов (атака DHCP Starvation).

**Условия успеха:**.

 - Клиент получает IP-адрес от нелегального DHCP-сервера быстрее.
   чем от легитимного DHCP-сервера. 
 - Легитимный сервер исчерпал пул выдаваемых адресов (атака DHCP Starvation).

 Атака **DHCP Starvation**: 

 - Злоумышленник запрашивает IP-адрес у DHCP-сервера и получает его.
  - MAC-адрес злоумышленника меняется, и он запрашивает следующий, другой IP-адрес, маскируясь под нового клиента.
 - Эти действия повторяются до тех пор, пока весь пул IP-адресов на сервере не будет исчерпан.

**Атакующие средства для DHCP starvation**
- [DHCPig](https://github.com/kamorin/DHCPig)
- nmap для поиска DHCP-сервера (`nmap -n --script=broadcast-dhcp-discover`)
- модули metasploit ([example](https://digi.ninja/metasploit/dns_dhcp.php))
- использование scapy для атаки на DHCP starvation ([пример](https://github.com/shreyasdamle/DHCP-Starvation-))

**Атакующие инструменты для подмены DHCP**
 - [yersinia](https://kalilinuxtutorials.com/yersinia/)
 - [mitmf](https://github.com/byt3bl33d3r/MITMf)
 - [Ettercap](https://www.ettercap-project.org/)
 
 

**Техника защиты**

- *Включить DHCP snooping*.

Это функция коммутатора L2, предназначенная для защиты от DHCP-атак. Например, от атаки DHCP spoofing или атаки DHCP starvation.

На коммутаторах Cisco:
- *Switch(config)#ip dhcp snooping vlan 10* - включение DHCP snooping для vlan10. 
- *Switch(config)# interface fa 0/1* - переход к настройкам конкретного интерфейса
- *Switch(config-if)#ip dhcp snooping trust* - настройка доверенных портов на интерфейсе (по умолчанию все порты являются ненадежными, DHCP-сервер не должен к ним подключаться).
- *Switch(config)#ip dhcp-server 10.84.168.253* - указание адреса доверенного DHCP-сервера, доступ к которому осуществляется через доверенный порт.

**Важно.** По умолчанию после включения DHCP snooping на коммутаторе включается проверка соответствия MAC-адресов. Коммутатор проверяет, совпадает ли MAC-адрес в DHCP-запросе с MAC-адресом клиента. Если они не совпадают, коммутатор отбрасывает пакет.

> [Как работает DHCP](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)  
> [DHCP wireshark sample](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=dhcp.pcap)

### Rogue DHCP (DHCPv6)
**Сложность:** Низкая  
**Актуальность:** Высокая  
**Описание:**  
Ipv6-клиент посылает сообщение *Solicit* на адрес All_DHCP_Relay_Agents_and_Servers для поиска доступных DHCP-серверов. Любой сервер, удовлетворяющий требованиям клиента, отвечает сообщением *Advertise*. Затем клиент выбирает один из серверов и посылает на него сообщение *Request* с запросом на подтверждение назначения адресов и другой конфигурационной информации. В ответ сервер посылает сообщение *Reply*, содержащее подтвержденные адреса и конфигурацию.  

Эта схема похожа на DHCPv4, поэтому основная задача злоумышленника - использовать поддельный DHCPv6-сервер для перенаправления трафика жертвы на себя.  

Злоумышленник может перехватить сообщение клиента DHCP solicit и ответить на него, выдавая себя за DHCPv6-сервер, и назначить учетные данные (например, DNS-адрес), которые будут использоваться жертвой. 

**Инструменты атаки**

- [mitm6](https://github.com/fox-it/mitm6)
- некоторые скрипты scapy python ([example](https://cciethebeginning.wordpress.com/2012/01/27/dhcpv6-fake-attack/))
- [snarf](https://github.com/purpleteam/snarf)

**Техника защиты**

- В устройствах cisco включите политику защиты dhcpv6 ([пример](https://community.cisco.com/t5/networking-documents/understanding-dhcpv6-guard/ta-p/3147653)).
- отключите Ipv6, если вы его не используете

## Беспроводные сети
### Атаки на карму (Wi-Fi)

**Сложность:** Низкая  
**Актуальность:** Высокая  
**Описание:**  
Атака KARMA использует особенности клиентов, посылающих запросы, для определения того, какие беспроводные сети находятся поблизости. 

Точка доступа Wi-Fi периодически посылает запрос-маяк с указанием SSID, идентифицирующего сеть Wi-Fi. Когда клиент получает кадр маяка с SSID, который он запомнил, он может быть ассоциирован с беспроводной сетью.
Уязвимые клиентские устройства передают в эфир "список предпочитаемых сетей" (PNL), содержащий SSID точек доступа, к которым они ранее подключались и готовы автоматически переподключиться без вмешательства пользователя. Эти сообщения могут быть приняты любой точкой доступа WiFi в радиусе действия. Атака KARMA заключается в том, что точка доступа получает этот список и присваивает себе SSID из PNL, становясь, таким образом, злым двойником точки доступа, которой клиент уже доверяет.

В результате клиент подключается к сети, отличной от той, на которую рассчитывает пользователь. И теперь злоумышленник может проводить MITM- или другие атаки на клиентскую систему.

*Однако в настоящее время* большинство современных сетевых менеджеров приняли меры против атаки KARMA, перейдя на пассивное сканирование; вместо произвольной рассылки запросов-зондов сетевые менеджеры теперь ожидают получения маячка с известным ESSID, прежде чем подключиться к беспроводной сети. В то время как эта контрмера снизила эффективность атаки KARMA, вторая функция, используемая KARMA, - флаг Auto-Connect, позволяющий станциям автоматически присоединяться к ранее подключенным сетям, - осталась нетронутой практически во всех современных операционных системах.

Злоумышленник, угадавший SSID в списке предпочитаемых сетей устройства-жертвы, сможет передать соответствующий кадр маяка и заставить это устройство автоматически подключиться к контролируемой злоумышленником точке доступа. В более сложном варианте атаки злоумышленник может использовать "словарь" распространенных SSID, к которым жертва, вероятно, подключалась в прошлом.

[Как работает атака KARMA?](https://www.justaskgemalto.com/en/karma-attack-work-former-ethical-hacker-jason-hart-explains/)

**Инструменты атаки**

+ *[Wifiphisher](https://github.com/wifiphisher/wifiphisher)*.  
Rogue Access Point Framework 

+ *[hostapd-mana](https://github.com/sensepost/hostapd-mana/)*  
Hostapd-mana - это многофункциональный инструмент для создания неавторизованных точек доступа к wifi. Он может использоваться для множества целей, от отслеживания и деанонимизации устройств (ака Snoopy), сбора корпоративных учетных данных с устройств, пытающихся подключиться к EAP (ака WPE), до привлечения как можно большего числа устройств для проведения MitM-атак.

+ *[WIFI PINEAPPLE](https://shop.hak5.org/products/wifi-pineapple)*.  
Инструментарий несанкционированной точки доступа и WiFi pentest.  
Как усилить атаку MK5 Karma с помощью модуля Dogma PineAP [здесь](https://www.hak5.org/episodes/hak5-gear/the-next-gen-rogue-access-point-pineap)].

+ *[FruityWIFI](http://fruitywifi.com/index_eng.html)*.  
FruityWiFi - это инструмент с открытым исходным кодом для аудита беспроводных сетей. Он позволяет проводить расширенные атаки как непосредственно через веб-интерфейс, так и путем отправки на него сообщений.  
Изначально приложение было создано для использования с Raspberry-Pi, но оно может быть установлено на любую систему на базе Debian.

**Техника защиты**

+ Обращайте внимание на сети Wi-Fi, к которым подключается ваше устройство  
+ Не используйте открытый Wi-Fi в общественных местах или используйте его очень редко  
+ Создание зашифрованных соединений (VPN и т.д.)  


### Rogue BTS (GSM)

## Техника атаки
## Снайпинг данных

** Инструменты атаки:**

* [wireshark](https://www.wireshark.org)
* [`net-creds`](https://github.com/DanMcInerney/net-creds)

## Инъекции в данные
### Вредоносный JS в HTML
### HTA

## Модификация данных
### Wsus
### DNS hijacking

## Заметки хакера
## Разница между стеками технологий (или почему большинство этих атак невозможно выполнить с ноутбука)
Спасибо [@serjepatoff](https://github.com/serjepatoff) за объяснение:  
В сетевом оборудовании используются одни и те же процессоры общего назначения. MIPS или ARM для базовых SOHO-маршрутизаторов, многоядерные x86 в более серьезных коробках. Разница заключается в сетевых картах с несколькими аппаратными очередями и специальными методами взаимодействия NIC<->программное обеспечение (явная кольцевая буферизация, активное использование DMA).

Поэтому нельзя просто подключиться к сети и включить спуфинг, он может сразу же вывести сеть из строя. Сетевой адаптер маленького ноутбука просто не справится с большим потоком данных и начнет их отбрасывать. Необходимо выбрать оптимальное количество хостов, которые можно подменить одновременно (~<4).

### Устройство атаки  
Возможный кандидат: MikroTik hAP AC

# SSLStrip, SSLStrip+, HSTS

***SSLStrip*** - это техника, которая заменяет защищенное (HTTPS) соединение на открытое (HTTP).
Эта атака также известна как HTTP-downgrading.

Она перехватывает HTTP-трафик и при обнаружении перенаправлений или ссылок на сайты, использующие HTTPS, прозрачно удаляет их.

Вместо того чтобы жертва напрямую подключалась к сайту, она подключалась к злоумышленнику, а тот инициировал обратное подключение к сайту. Перехватчик устанавливал зашифрованное соединение с веб-сервером по протоколу HTTPS и передавал трафик обратно посетителю сайта в незашифрованном виде. 

***Но*** с появлением HSTS это уже не работает. Точнее, он не работает там, где включена HSTS.

HTTP Strict Transport Security ([HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)) - это механизм политики веб-безопасности, позволяющий защитить сайты от атак с понижением протокола (SSL stripping). Он позволяет веб-серверам объявить, что веб-браузеры должны взаимодействовать с ним только через защищенные соединения HTTPS и никогда - через небезопасный протокол HTTP. HSTS является протоколом IETF, отслеживающим стандарты, и описан в RFC 6797.

HSTS работает следующим образом: сервер отвечает специальным заголовком Strict-Transport-Security, который содержит ответ, сообщающий клиенту, что при каждом повторном подключении к сайту он должен использовать HTTPS. Этот ответ содержит поле "max-age", которое определяет, как долго должно действовать это правило с момента его последнего просмотра.

Также в нем есть `includeSubDomains` (необязательный параметр).
Если этот необязательный параметр указан, то данное правило будет применяться и ко всем поддоменам сайта.

Но не все настраивают HSTS одинаково.

Именно так и появился ***SSLstrip++***.

Это инструмент, который прозрачно перехватывает HTTP-трафик в сети, следит за HTTPS-ссылками и перенаправлениями, а затем преобразует эти ссылки либо в похожие на HTTP-ссылки, либо в похожие на них HTTPS-ссылки. 

Одним из недостатков HSTS является то, что для безопасного соединения с конкретным сайтом необходимо знать о предыдущем соединении. Когда посетитель впервые подключается к сайту, он не получает правила HSTS, которое предписывает ему всегда использовать HTTPS. Только при последующих подключениях браузер посетителя будет знать о правиле HSTS, которое предписывает ему подключаться по HTTPS.

Одним из потенциальных решений этой проблемы являются ***HSTS Preload Lists***, которые эффективно работают за счет жесткого кодирования списка сайтов, подключение к которым должно осуществляться только по HTTPS. 

В исходном коде Google Chrome есть файл, содержащий жестко закодированный файл со списком HSTS-свойств для всех доменов в списке предварительной загрузки. Каждая запись отформатирована в JSON.


**Инструменты атаки**

+ [sslstrip](https://github.com/moxie0/sslstrip)  
sslstrip - это MITM-инструмент, реализующий атаки на зачистку SSL от Moxie Marlinspike.

+ [sslstrip2](https://github.com/LeonardoNve/sslstrip2)  
Это новая версия [Moxie´s SSLstrip] (http://www.thoughtcrime.org/software/sslstrip/) с новой возможностью обхода механизма защиты HTTP Strict Transport Security (HSTS).

**Техника защиты**

[Для разработчиков - 6-ступенчатый "счастливый путь" к HTTPS](https://www.troyhunt.com/the-6-step-happy-path-to-https/)
