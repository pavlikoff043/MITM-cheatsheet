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

**Attack tools**  
* [t50](https://gitlab.com/fredericopissarra/t50) - a multi-protocol tool for injecting traffic and for network penetration testing. Among many other protocols, it supports RIP.
  
**Defence technics**  
If router is not configured to authenticate RIPv2 messages, it will accept RIPv1 and RIPv2 unauthenticated messages. The most secure configuration in this way is to set up RIPv2 authentication so that router should not be accepting RIPv1 and v2 unauthenticated messages and so making an unauthenticated router unable to inject a route. This mechanism is described in [RFC 2082 - RIP-2 MD5 Authentication](https://tools.ietf.org/html/rfc2082), but, it describes the usage of MD5, which is acknowledged to be a weak hashing function. The better one, which means the use of SHA-1 is described in [RFC 4822 - RIPv2 Cryptographic Authentication](https://tools.ietf.org/html/rfc4822).  

Unfortunately, RIPv2 supports only Plain-text and MD5 Authentication. The first one is useless in case of sniffing the network, MD5 Auth is better in case of a passive attacker, intercepting packets, as it doesn't transfer password in plain text.  
[The Configuration of RIPv2 Authentication guide](https://www.cisco.com/c/en/us/support/docs/ip/routing-information-protocol-rip/13719-50.html#md5) describes how to set this feature on *Cisco* devices.  
The guide for setting MD5 authentication for *Mikrotik* is present [here](https://mikrotik.com/documentation/manual_2.6/Routing/RIP.html).
The guide for setting MD5 authentification on *Juniper* devices is present [here](https://www.juniper.net/documentation/en_US/junos/topics/topic-map/rip-authentication.html).

Also, `passive-interface` feature should be used on the access interfaces, which communicate to end devices.  
[Mikrotik's documentation](https://wiki.mikrotik.com/wiki/Manual:Routing/RIP#Interface) on setting `passive interface` feature.  
[Cisco's documentation](https://networklessons.com/cisco/ccna-routing-switching-icnd1-100-105/rip-passive-interface) on setting `passive interface` feature.  
[Juniper's documentation](https://www.juniper.net/documentation/en_US/junose15.1/topics/reference/command-summary/passive-interface.html) on setting `passive-interface` feature.  

**Related RFCs:**  
[RFC 1388 - RIP Version 2 Carrying Additional Information](https://tools.ietf.org/html/rfc1388)  
[RFC 4822 - RIPv2 Cryptographic Authentication](https://tools.ietf.org/html/rfc4822)  
[RFC 2453 - RIP Version 2](https://tools.ietf.org/html/rfc2453)  
[RFC 2080 - RIPng for IPv6](https://tools.ietf.org/html/rfc2080).  

### OSPF Routing Table Poisoning
**Сomplexity:** High  
**Relevance:** High  
**Conditions:**  
**Description:**  
**Attack tools**  
**Defence technics**  

### EIGRP Routing Table Poisoning
**Complexity:** Medium  
**Relevance:** Medium  
**Conditions:** EIGRP protocol implemented on the network; no EIGRP messages authentication set up  
**Description:**  
EIGRP stands for Enhanced Interior Gateway Routing Protocol. It is a proprietary Cisco’s distance vector routing protocol, relying on Diffused Update Algorithm - DUAL. The main purpose of this protocol is to dynamically update the routing table and propagate the routes to other routers.  
The main security issue is possible in case of spoofing data in *Update* message, e.g. to inject a non-legitimate route. In this case the router's routing table gets changed to make it pass the traffic through the device, controlled by the attacker and so the MitM attack is present.  

**Attack tools**  
* [Eigrp Tools](http://www.hackingciscoexposed.com/?link=tools)  
A perl script which allows to craft EIGRP packets and send them on network. It even allows set the K1-K4 metrics, all the flags and fields of EIGRP packet. The script requires `libnet-rawip-perl` and `libnetpacket-perl` packets to be installed. Some examples of usage:  

	`./eigrp.pl --sniff --iface eth0`  
	  perform a sniff on eth0 interface  
	`./eigrp.pl --file2ip update.dat --source 192.168.7.8`  
	  replay the traffic from file  
	`./eigrp.pl --update --external --as 65534 --source 192.168.7.8`  
	  send and Update message  

* [EIGRP Security Tool](https://sourceforge.net/projects/eigrpsectool/)  
A python script, which allows to craft and send different EIGRP packets. The problem is that attempts to launch the script were unsuccessful due to lack of scapy_eigrp module which wasn't found. Also authors didn't write any documentation for the tool even in the 
[research description](https://docs.google.com/document/d/1ZVNwi5KRkbY_PxMoODTvwSh3qpzdqiRM9Q4qppP2DvE/edit).

* [t50](https://gitlab.com/fredericopissarra/t50) - a multi-protocol tool for injecting traffic and for network penetration testing. Among many other protocols, it supports EIGRP traffic manipulating.

**Defence techniques**  
To protect a network from untrusted route propagations, EIGRP provides a mechanism for authenticating router updates. It uses MD5-keyed digest to sign each packet to prevent unauthorized devices from sending updates to the network. It protects legitimate routers from non-legitimate router updates and from router spoofing. The key is just a defined string, which must be set on other devices which are meant to be legitimate. The detailed guide on EIGRP MD5 Authentication setup can be found [here](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/82110-eigrp-authentication.html#maintask1).  

Unfortunately, MD5 is acknowledged to be a weak hashing algorithm due to hash collisions. Cisco devices also support `hmac-sha-256` EIGRP Updates Authentification. The hash collision attack on SHA-256 is much more complex than for MD5. The guide to EIGRP HMAC-SHA-256 Authentication can be found [here](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/configuration/15-mt/ire-15-mt-book/ire-sha-256.pdf).  

The stub EIGRP routing area can be set up as it let's determine the types of routes the stub router should receive queries or not. More information on EIGRP Stub Routing can be found [here](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_eigrp/configuration/15-mt/ire-15-mt-book/ire-eigrp-stub-rtg.html).  

Another best practice to reduce unwanted traffic in a network is to set up passive interfaces. `passive-interface` feature should be set on access interfaces, which communicate not to network devices, but to end devices. The instruction on setting `passive-interface` on EIGRP and explaination on how it works is presented in [Cisco's documentation page](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/13675-16.html).  

### ICMP Redirect
**Сomplexity:** Medium  
**Relevance:** Medium  
**Description:**  
One of the purposes of the ICMP Protocol is to dynamically change the routing table of the end network systems.
Dynamic remote management routing was originally conceived to prevent possible send a message to a non-optimal route, as well as to increase fault tolerance of the Network as a whole. It was assumed that the network segment can be connected to the Internet  through several routers (not through one as it usually happens). In this case, we can address the external network through any of the nearest routers. For example, to *some_host.site* the shortest route passes through the "router A" and to the *another.site* - through the "router B". 

If one of the routers fails, communication with the outside world is possible through another router. 
As the "ICMP Redirest attack", we change the route to some site (DNS Name) in the routing table of node A (victim) so that the traffic from node A to some site goes through hacker PC

**Conditions of success:**  
- The IP address of the new router must be on the same subnet as the attacked host itself.
- A new route cannot be added for an IP address that is on the same subnet as the host itself.
- OS must support and process ICMP redirect packets. By default ICMP redirect enabled in Windows (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect)  
and in some Linux distros (cat /proc/sys/net/ipv4/conf/all/accept_redirects)

**Attack tools**

- [Responder](https://github.com/SpiderLabs/Responder) ([example](https://github.com/SpiderLabs/Responder/blob/master/tools/Icmp-Redirect.py))
- Hping3 ([example](https://gist.github.com/githubfoam/91bd46b68c7ee1fe465e9f743a24d140))
- [Mitmf](https://github.com/byt3bl33d3r/MITMf)
- Bettercap ([documentation](https://www.bettercap.org/legacy/))

**Defence technics**

- Disable icmp redirect ([example](https://sbmlabs.com/notes/icmp_redirect_attack/))

## L4+

### NetBIOS (LLMNR) spoofing
**Сomplexity:** Low  
**Relevance:** High  
**Description:**  
If a windows client cannot resolve a hostname using DNS, it will use the Link-Local Multicast Name Resolution ([LLMNR](https://docs.microsoft.com/en-us/previous-versions//bb878128(v=technet.10))) protocol to ask neighbouring computers. LLMNR can be used to resolve both IPv4 and IPv6 addresses. 

If this fails, NetBios Name Service ([NBNS](https://wiki.wireshark.org/NetBIOS/NBNS)) will be used. NBNS is a similar protocol to LLMNR that serves the same purpose. The main difference between the two is NBNS works over IPv4 only. 

The problem of this pretty cool thing is that when LLMNR or NBNS are used to resolve a request, any host on the network who knows the IP of the host being asked about can reply. Even if a host replies to one of these requests with incorrect information, it will still be regarded as legitimate.

The attacker may request NTLM authentication from the victim, which will cause the victim's device to send an NTLM hash, which can then be used for brute force attack.

<details>
 <summary>Also there is a chance to perform WPAD spoofing.</summary>

WPAD spoofing can be referred to as a special case of LLMNR- and NBNS-spoofing. Web Proxy Auto Discovery protocol is used for automatic configuration of HTTP proxy server. 

The device sends an LLMNR/NBNS request with a wpad host, obtains the corresponding IP address and tries to access the wpad.dat file containing information about proxy settings via HTTP.

As a result, an attacker can perform LLMNR/NBNS spoofing and provide the victim with his own wpad.dat file, resulting in all HTTP and HTTPS traffic going through the attacker.</details>

[Quick tutorial to grab clear text credentials](https://www.trustedsec.com/2013/07/wpad-man-in-the-middle-clear-text-passwords/)  
[How Microsoft Windows’s name resolution services work and how they can be abused](https://trelis24.github.io/2018/08/03/Windows-WPAD-Poisoning-Responder/)

**Attack tools**

* [Responder](https://github.com/SpiderLabs/Responder)  
It can answer LLMNR and NBNS queries giving its own IP address as the destination for any hostname requested. Responder has support for poisoning WPAD requests and serving a valid wpad.dat PAC file.

+ [Mitm6](https://github.com/fox-it/mitm6)  
mitm6 is a pentesting tool which is designed for WPAD spoofing and credential relaying. 

+ [Inveigh](https://github.com/Kevin-Robertson/Inveigh)  
Inveigh is a PowerShell ADIDNS/LLMNR/NBNS/mDNS/DNS spoofer and man-in-the-middle tool designed to assist penetration testers/red teamers that find themselves limited to a Windows system.
	```powershell
	Import-Module .\Inveigh.psd1
	Invoke-Inveigh -NBNS Y -mDNS Y -FileOutput Y -ConsoleOutput Y -SMB Y 
	``` 

+ [Metasploit modules](https://github.com/rapid7/metasploit-framework)  
[auxiliary/spoof/llmnr/llmnr_response](https://www.rapid7.com/db/modules/auxiliary/spoof/llmnr/llmnr_response),  
[auxiliary/spoof/nbns/nbns_response](https://www.rapid7.com/db/modules/auxiliary/spoof/nbns/nbns_response) 

**Defence technics**

+ Disable LLMNR and NBNS. You can do it using [GPO](https://en.wikipedia.org/wiki/Group_Policy)  
([how to do it here](http://woshub.com/how-to-disable-netbios-over-tcpip-and-llmnr-using-gpo/))  
+ Create DNS entry with “WPAD” that points to the corporate proxy server. So the attacker won’t be able to manipulate the traffic.  
+ Disable “Autodetect Proxy Settings”


### DHCP spoofing 
**Сomplexity:** Moderate  
**Relevance:** Moderate  
**Description:**    
The purpose of this attack is to *use the attacker's host or device as the default gateway* and to force clients to use a false Domain Name Service (DNS) and a Windows Internet name service (WINS server) configured by the attacker. The attacker's task is to configure a fake DHCP server on the network to provide DHCP addresses to clients and exhausted the pool of IP addresses from other legitimate DHCP servers (DHCP Starvation attack).

**Conditions of success:**

 - The client receives an IP address from a Rogue DHCP server faster
   than from a legitimate DHCP server. 
 - The legitimate server has exhausted the pool of addresses to be issued (DHCP Starvation attack).

 **DHCP Starvation attack**: 

 - The attacker requests an IP address from the DHCP server and receives it
  - The MAC address of the attacker changes and it requests the next, different IP address, masked as a new client
 - These actions are repeated until the entire pool of IP addresses on the server is   exhausted.

**Attack tools for DHCP starvation**
- [DHCPig](https://github.com/kamorin/DHCPig)
- nmap to find DHCP server (`nmap -n --script=broadcast-dhcp-discover`)
- metasploit modules ([example](https://digi.ninja/metasploit/dns_dhcp.php))
- use scapy for DHCP starvation attack ([example](https://github.com/shreyasdamle/DHCP-Starvation-))

**Attack tools for DHCP spoofing**
 - [yersinia](https://kalilinuxtutorials.com/yersinia/)
 - [mitmf](https://github.com/byt3bl33d3r/MITMf)
 - [Ettercap](https://www.ettercap-project.org/)
 
 

**Defence technics**

- *Enable DHCP snooping*

This is a L2 switch function designed to protect against DHCP attacks. For example, a DHCP spoofing attack or DHCP starvation attack.

On Cisco Switches:
- *Switch(config)#ip dhcp snooping vlan 10* - enable DHCP snooping for vlan10 
- *Switch(config)# interface fa 0/1* - go to the settings of the specific interface
- *Switch(config-if)#ip dhcp snooping trust* - setting up trusted ports on the interface (by default all ports are unreliable, the DHCP server should not be connected to them).
- *Switch(config)#ip dhcp-server 10.84.168.253* - Specify the address of the trusted DHCP server, which is accessible through the trusted port.

**Important.** By default, after enabling DHCP snooping, the switch is enabled to check for MAC address matching. The switch checks whether the MAC address in the DHCP request matches the client's MAC address. If they do not match, the switch discards the packet.

> [How DHCP works](https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol)  
> [DHCP wireshark sample](https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=dhcp.pcap)

### Rogue DHCP (DHCPv6)
**Сomplexity:** Low  
**Relevance:** High  
**Description:**  
The Ipv6 client sends a *Solicit* message to the All_DHCP_Relay_Agents_and_Servers address to find available DHCP servers. Any server that can meet the client's requirements responds with an *Advertise* message. The client then chooses one of the servers and sends a *Request* message to the server asking for confirmed assignment of addresses and other configuration information.The server responds with a *Reply* message that contains the confirmed addresses and configuration.  

This schema looks simular to DHCPv4 so the main goal for the attacker is to use fake DHCPv6 server to redirect victims traffic to himself.  

The attacker can catch client DHCP solicit message and can actually reply, pretending that he is the DHCPv6 server and assign credentials (such as the DNS address) to be used by victim. 

**Attack tools**

- [mitm6](https://github.com/fox-it/mitm6)
- some scapy python scripts ([example](https://cciethebeginning.wordpress.com/2012/01/27/dhcpv6-fake-attack/))
- [snarf](https://github.com/purpleteam/snarf)

**Defence technics**

- In cisco devices enable dhcpv6 guard policy ([example](https://community.cisco.com/t5/networking-documents/understanding-dhcpv6-guard/ta-p/3147653))
- disable Ipv6 if you don't use it

## Wireless
### Karma attacks (Wi-Fi)

**Сomplexity:** Low  
**Relevance:** High  
**Description:**  
The KARMA attack uses the peculiarities of the clients who send requests to determine which wireless networks are nearby. 

The Wi-Fi Access Point periodically sends a beacon request indicating the network SSID that identifies the Wi-Fi network. When a client receives a beacon frame with an SSID that it remembers, it can be associated with the wireless network.
Vulnerable client devices broadcast a "preferred network list" (PNL), which contains the SSIDs of access points to which they have previously connected and are willing to automatically reconnect without user intervention. These broadcasts may be received by any WiFi access point in range. The KARMA attack consists in an access point receiving this list and then giving itself an SSID from the PNL, thus becoming an evil twin of an access point already trusted by the client.

As a result, the client connects to a different network than the one the user expects. And now the attacker can perform MITM or other attacks on the client system.

*However, nowadays*, most modern network managers have taken countermeasures against the KARMA attack by switching to passive scanning; instead of arbitrarily sending probe request frames, network managers now wait to receive a beacon frame with a familiar ESSID before associating with a wireless network. While this countermeasure has hampered the effectiveness of the KARMA attack, the second feature exploited by KARMA, the Auto-Connect flag that enables the stations to automatically join previously connected networks, was left intact in almost every modern Operating System.

An attacker that can guess the SSID  in the victim device's Preferred Network List, will be able to broadcast the corresponding beacon frame and have that device automatically associate with an attacker-controlled access point. In a more sophisticated version of the attack, the adversary may use a "dictionary" of common SSIDs, that the victim has likely connected to in the past.

[How does a KARMA attack work?](https://www.justaskgemalto.com/en/karma-attack-work-former-ethical-hacker-jason-hart-explains/)

**Attack tools**

+ *[Wifiphisher](https://github.com/wifiphisher/wifiphisher)*  
The Rogue Access Point Framework 

+ *[hostapd-mana](https://github.com/sensepost/hostapd-mana/)*  
Hostapd-mana is a featureful rogue wifi access point tool. It can be used for a myriad of purposes from tracking and deanonymising devices (aka Snoopy), gathering corporate credentials from devices attempting EAP (aka WPE) or attracting as many devices as possible to connect to perform MitM attacks.

+ *[WIFI PINEAPPLE](https://shop.hak5.org/products/wifi-pineapple)*  
The rogue access point and WiFi pentest toolkit.  
How to reinforce the MK5 Karma attack with the Dogma PineAP module [here](https://www.hak5.org/episodes/hak5-gear/the-next-gen-rogue-access-point-pineap).

+ *[FruityWIFI](http://fruitywifi.com/index_eng.html)*  
FruityWiFi is an open source tool to audit wireless networks. It allows the user to deploy advanced attacks by directly using the web interface or by sending messages to it.  
Initialy the application was created to be used with the Raspberry-Pi, but it can be installed on any Debian based system.

**Defence technics**

+ Pay attention to the Wi-Fi networks that your device connects to  
+ Don't use open wifi in public areas, or use it very sparingly  
+ Creating encrypted connections (VPN, etc.)  


### Rogue BTS (GSM)

# Attack technics
## Data sniffing

**Attack tools:**

* [wireshark](https://www.wireshark.org)
* [`net-creds`](https://github.com/DanMcInerney/net-creds)

## Injections in data
### Malicious JS in HTML
### HTA

## Data modification
### Wsus
### DNS hijacking

# Hacker notes
## Difference between technology stack (or why most of that attack imposible from your notebook)
Thanks to [@serjepatoff](https://github.com/serjepatoff) for explanation:  
Network equipment has the same general-purpose CPUs. MIPS or ARM for basic SOHO routers, multicore x86 in more serious boxes. It's the NIC with multiple hardware queues and special methods of NIC<->software communication (explicit ring–buffering, heavy use of DMA) that make a difference.

So you can't just connect to the network and turn on the spoofing, it can put the network down right away. Your small notebook network adapter simply cannot cope with a large data stream and will start to drop them. You need to choose the optimal number of hosts that you can spoof at the same time(~<4).

### Attack device  
Possible candidate: MikroTik hAP AC

#  SSLStrip, SSLStrip+, HSTS

***SSLStrip*** is a technique that replaces a secure (HTTPS) connection with an open (HTTP) connection.
This attack is also known as HTTP-downgrading

It intercepted HTTP traffic and whenever it spotted redirects or links to sites using HTTPS, it would transparently strip them away.

Instead of the victim connecting directly to a website; the victim connected to the attacker, and the attacker initiated the connection back to the website. The interceptor made the encrypted connection to back to the web server in HTTPS, and served the traffic back to the site visitor unencrypted 

***But*** it doesn't work anymore with the advent of HSTS. More precisely, it doesn't work where HSTS is enabled.

HTTP Strict Transport Security ([HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security)) is a web security policy mechanism that helps to protect websites against protocol downgrade attacks (SSL stripping). It allows web servers to declare that web browsers should interact with it using only secure HTTPS connections, and never via the insecure HTTP protocol. HSTS is an IETF standards track protocol and is specified in RFC 6797.

The HSTS works by the server responding with a special header called Strict-Transport-Security which contains a response telling the client that whenever they reconnect to the site, they must use HTTPS. This response contains a "max-age" field which defines how long this rule should last for since it was last seen.

Also It has `includeSubDomains` (optional).
If this optional parameter is specified, this rule applies to all of the site's subdomains as well.

But not everyone sets up HSTS the same way.

That's how ***SSLstrip++*** came about.

It's a tool that transparently hijack HTTP traffic on a network, watch for HTTPS links and redirects, then map those links into either look-alike HTTP links or homograph-similar HTTPS links. 

One of the shortcomings of HSTS is the fact that it requires a previous connection to know to always connect securely to a particular site. When the visitor first connects to the website, they won't have received the HSTS rule that tells them to always use HTTPS. Only on subsequent connections will the visitor's browser be aware of the HSTS rule that requires them to connect over HTTPS.

***HSTS Preload Lists*** are one potential solution to help with these issues, they effectively work by hardcoding a list of websites that need to be connected to using HTTPS-only. 

Inside the source code of Google Chrome, there is a file which contains a hardcoded file listing the HSTS properties for all domains in the Preload List. Each entry is formatted in JSON.


**Attack tools**

+ [sslstrip](https://github.com/moxie0/sslstrip)  
sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping attacks.

+ [sslstrip2](https://github.com/LeonardoNve/sslstrip2)  
This is a new version of [Moxie´s SSLstrip] (http://www.thoughtcrime.org/software/sslstrip/) with the new feature to avoid HTTP Strict Transport Security (HSTS) protection mechanism.

**Defence technics**

[For developers - The 6-Step "Happy Path" to HTTPS](https://www.troyhunt.com/the-6-step-happy-path-to-https/)
