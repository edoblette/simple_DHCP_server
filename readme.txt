README SERVEUR DHCP
PROJET ROUTAGE - M. SPATHIS
Ed. OBLETTE

1. SERVER_DHCP :
C’est la classe principale du projet, la classe d’où est lancé le serveur DHCP.

	1.1 SERVER :
	C’est la principale fonction du projet, tout simplement parce que c’est la fonction qui lance le serveur DHCP.

	1.2 START :
	Cette fonction sert au lancement du serveur ainsi qu’au bon déroulement des échanges de messages entre serveur et client.
	
	1.3 STOP :
	Et donc celle-ci sert à arrêter le serveur.
	
	1.4 GUI :
	Dans cette fonction nous ajoutons toutes les commandes que nous voulons disponibles sur le serveur. 
	Par exemple “usage”, qui renvoie les adresses IP allouées et les adresses MAC auxquelles elles sont allouées, 
	ou “available” qui renvoie toutes les adresses IP encore disponibles..
	
	1.5 IP_ADDR_FORMAT :
	Cette fonction sert à récupérer l’adresse IP d’une machine connectée au réseau local du serveur DHCP
	puis à modifier son format de façon à ce que celle-ci s’intègre parfaitement au reste du paquet d’information envoyé.
	
	1.6 MAC_ADDR_FORMAT :
	Cette fonction sert à récupérer l’adresse MAC d’une machine connectée au réseau local du serveur DHCP
	puis à modifier son format de façon à ce que celle-ci s’intègre parfaitement au reste du paquet d’information envoyé.
	
	1.7 PACKET_ANALYSER :
	Cette fonction sert tout simplement à récupérer un message venant d’un client.
	
	1.8 SET_OFFER :
	Cette fonction envoie le message “offer” à un client dont le serveur a reçu un message “discover”.
	Le serveur lui offre donc une adresse IP de libre si le client n’a pas fait de demande spécifique.
	
	1.9 PACK_GET :
	Cette fonction renvoie l’acknowledgment de l’allocation de l’adresse IP indiquée dans le message “request” reçu du client.
	
	1.10 INFO_MSG :
	Cette fonction ajoute au journal tout évènement auquel le serveur a été confronté, que ce soit un évènement manuel ou automatique.
	
	1.11 ERROR_MSG :
	Cette fonction renvoie tel ou tel message d’erreur selon l’erreur rencontrée par le serveur,
	par exemple quand plus aucune adresse IP est disponible, l’erreur “0”, ça renverra: “ERROR (No more IPs available)”.
	
	1.12 CLEAR_LOG :
	Cette fonction efface tout le contenu du journal. Active quand la commande “erase” est lancée.

2. IPVECTOR :
Dans cette classe sont toutes les fonctionnalités nécessaires pour une allocation satisfaisante d’adresses IP aux clients
en réquisitionnant une au serveur DHCP, et finalement nécessaires au bon fonctionnement du serveur lui-même.

	2.1 INIT :
	Initialise tous les arguments nécessaires au lancement du serveur DHCP.

	2.2 ADD_IP :
	Cette fonction met en place un nombre d’adresses IP disponibles équivalent au nombre passé à l’argument “range”.
	Elle les place dans un dictionnaire dont nous allons nous servir pour les allouer à des clients en demandant.

	2.3 UPDATE_IP :
	Cette fonction met à jour la liste d’adresses IP disponibles suivant celles qui sont allouées.

	2.4 REMOVE_IP :
	Cette fonction retire une adresse IP de la liste.

	2.5 DETACH_IP :
	Cette fonction détache une adresse IP d’un client s’il elle est allouée.

	2.6 BAN_ADDR :
	Cette fonction bannit une adresse MAC, dont le serveur n’écoutera plus les messages.

	2.7 UNBAN_ADDR :
	Le contraire de la fonction précédente.

	2.8 GET_BANNED_ADRESSES :
	Cette fonction renvoie la liste des adresses mises au ban.

	2.9 GET_BROADCAST_ADRESS :
	Cette fonction renvoie l’adresse broadcast.

	2.10 GET_IP :
	Cette fonction trouve l’adresse IP précédemment allouée à un client.
	Si celui-ci n’en avait pas mais qu’il spécifie l’adresse à laquelle il veut être associé, cette fonction renverra cette adresse.
	Si nous ne nous trouvons dans aucun de ces cas, la fonction renvoie vers "get_free".

	2.11 GET_FREE :
	Cette fonction alloue une adresse IP disponible à un client en demandant, sans spécificité particulière.

	2.12 GET_IP_ALLOCATED :
	Cette fonction montre quelles adresses IP ont été allouées à quels clients.

	2.13 GET_IP_AVAILABLE :
	Cette fonction montre quelles adresses IP sont encore disponibles.

3. MAIN :
Dans le main nous spécifions directement les arguments à donner au serveur lors du lancement (affiché sur le terminal).
Également, le fichier du journal est ouvert pour écrire tous les évènements auquel est confronté notre serveur.
Puis le main lance le serveur et les deux threads, le premier étant celui qui exécute les fonctions DHCP
et le deuxième servant à l’affichage des informations.