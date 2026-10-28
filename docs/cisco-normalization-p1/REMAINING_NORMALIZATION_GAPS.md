# Lacunes de normalisation restantes

764 commandes natives (38 familles), 22 commandes partielles, 3 inconnues : **789 occurrences** sans normalisation complète. La totalité est indexée ci-dessous. Les coordonnées Cxxxx:Lnn se résolvent dans le CORPUS_MANIFEST.json de la mission précédente.

| Décision du périmètre natif restant | Familles | Occurrences |
|---|---:|---:|
| KEEP_NATIVE | 17 | 490 |
| NEEDS_REVIEW | 7 | 177 |
| EXTEND_MODEL P2 | 13 | 81 |
| MAP_EXISTING bloqué par dépendance | 1 | 16 |

Aucune famille P1 EXTEND_MODEL du plan ne reste sans implémentation. Les 40 familles et leurs 466 occurrences sont traitées. Les paramètres P2 ne sont pas consommés sous prétexte de partager une structure avec P1.

Les deux cas AAA restent en revue : négation antérieure suivie d’une activation explicite dans le même export et commande authentication login privilege-mode sans méthode IOS démontrée. Les 140 occurrences MMI et 35 IOAM gardent leurs valeurs natives. Ni correction de syntaxe, ni valeur de méthode, ni activation de service ne sont inventées.

Les 16 match community dépendent des 22 lignes de regex Cisco partiellement normalisées. La liste et son expression restent conservées sans certification de son langage. Les trois logging synchronous globaux restent inconnus, sans parent line inventé.

Limites générales : absence d’état RIB/FIB ou négocié, références hors export et sources incomplètes possibles, pas de validation sur toutes releases/plateformes, pas de moteur complet d’évaluation de route-maps. Le registre est conservé sans décodage non attesté ; http Call Home ne prouve pas absence de TLS. Un verdict de conformité doit tenir compte de ces inconnues.

## catalogue_alias — captured_unmapped — 2 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0043:L336, C0043:L337.

## catalogue_bgp_community_format — captured_unmapped — 11 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0001:L118, C0002:L122, C0004:L122, C0005:L119, C0007:L106, C0008:L110, C0009:L110, C0010:L112, C0011:L112, C0042:L175, C0043:L215.

## catalogue_boot_system — captured_unmapped — 2 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0042:L28, C0043:L28.

## catalogue_cache_enable — captured_unmapped — 2 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0042:L182, C0043:L222.

## catalogue_cache_entries — captured_unmapped — 2 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0042:L179, C0043:L219.

## catalogue_cache_timeout — captured_unmapped — 2 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0042:L180, C0043:L220.

## catalogue_call_home_contact — captured_unmapped — 21 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0064:L190, C0065:L193, C0066:L190, C0068:L254, C0069:L254, C0070:L255, C0071:L254, C0075:L279, C0076:L282, C0077:L279, C0103:L258, C0104:L253, C0105:L249, C0121:L252, C0122:L252, C0123:L326, C0124:L325, C0143:L253, C0144:L253, C0145:L300, C0146:L299.

## catalogue_console — captured_unmapped — 25 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0024:L11, C0025:L11, C0026:L11, C0027:L11, C0028:L11, C0029:L11, C0030:L11, C0068:L14, C0069:L14, C0070:L14, C0071:L14, C0075:L12, C0076:L12, C0077:L12, C0103:L13, C0104:L13, C0105:L13, C0121:L13, C0122:L13, C0123:L13, C0124:L13, C0143:L13, C0144:L13, C0145:L13, C0146:L13.

## catalogue_control_plane — captured_unmapped — 85 occurrences

Décision : KEEP_NATIVE ; priorité : P2. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0001:L173, C0002:L181, C0003:L108, C0004:L181, C0005:L177, C0006:L128, C0007:L139, C0008:L133, C0009:L133, C0010:L167, C0011:L160, C0012:L117, C0014:L120, C0015:L118, C0016:L101, C0017:L102, C0019:L202, C0020:L159, C0021:L187, C0022:L148, C0024:L188, C0025:L221, C0026:L214, C0027:L182, C0028:L182, C0029:L181, C0030:L183, C0031:L115, C0032:L120, C0033:L119, C0034:L120, C0042:L256, C0043:L319, C0044:L114, C0045:L114, C0064:L171, C0065:L174, C0066:L171, C0068:L226, C0069:L226, C0070:L227, C0071:L226, C0075:L260, C0076:L263, C0077:L260, C0089:L113, C0090:L113, C0103:L230, C0104:L234, C0105:L230, C0106:L119, C0107:L119, C0108:L119, C0109:L119, C0116:L115, C0117:L115, C0118:L115, C0119:L115, C0121:L224, C0122:L224, C0123:L298, C0124:L297, C0125:L118, C0126:L118, C0127:L118, C0128:L118, C0138:L114, C0139:L114, C0140:L114, C0141:L114, C0143:L225, C0144:L225, C0145:L272, C0146:L271, C0148:L121, C0149:L119, C0150:L119, C0151:L122, C0152:L122, C0153:L122, C0154:L122, C0160:L123, C0161:L123, C0162:L123, C0163:L123.

## catalogue_diagnostic — captured_unmapped — 28 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0024:L99, C0025:L106, C0026:L99, C0027:L99, C0028:L99, C0029:L99, C0030:L99, C0064:L88, C0065:L88, C0066:L88, C0068:L137, C0069:L137, C0070:L138, C0071:L137, C0075:L141, C0076:L141, C0077:L141, C0103:L136, C0104:L136, C0105:L136, C0121:L136, C0122:L136, C0123:L153, C0124:L152, C0143:L136, C0144:L136, C0145:L153, C0146:L152.

## catalogue_flow_aggregation — captured_unmapped — 2 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0042:L178, C0043:L218.

## catalogue_gatekeeper — captured_unmapped — 8 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0014:L128, C0015:L126, C0016:L109, C0017:L110, C0019:L210, C0020:L167, C0021:L195, C0022:L156.

## catalogue_gatekeeper_shutdown — captured_unmapped — 8 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0014:L129, C0015:L127, C0016:L110, C0017:L111, C0019:L211, C0020:L168, C0021:L196, C0022:L157.

## catalogue_ifindex — captured_unmapped — 2 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0042:L254, C0043:L317.

## catalogue_ioam — captured_unmapped — 35 occurrences

Décision : NEEDS_REVIEW ; priorité : P2. Sémantique/source non établie : maintien natif selon la décision initiale.

Preuves : C0031:L111, C0032:L116, C0033:L115, C0034:L116, C0044:L110, C0045:L110, C0089:L109, C0090:L109, C0106:L115, C0107:L115, C0108:L115, C0109:L115, C0116:L111, C0117:L111, C0118:L111, C0119:L111, C0125:L114, C0126:L114, C0127:L114, C0128:L114, C0138:L110, C0139:L110, C0140:L110, C0141:L110, C0148:L117, C0149:L115, C0150:L115, C0151:L118, C0152:L118, C0153:L118, C0154:L118, C0160:L119, C0161:L119, C0162:L119, C0163:L119.

## catalogue_license — captured_unmapped — 28 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0024:L98, C0025:L105, C0026:L98, C0027:L98, C0028:L98, C0029:L98, C0030:L98, C0064:L87, C0065:L87, C0066:L87, C0068:L136, C0069:L136, C0070:L137, C0071:L136, C0075:L140, C0076:L140, C0077:L140, C0103:L135, C0104:L135, C0105:L135, C0121:L135, C0122:L135, C0123:L152, C0124:L151, C0143:L135, C0144:L135, C0145:L152, C0146:L151.

## catalogue_memory_low — captured_unmapped — 21 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0064:L89, C0065:L89, C0066:L89, C0068:L138, C0069:L138, C0070:L139, C0071:L138, C0075:L142, C0076:L142, C0077:L142, C0103:L137, C0104:L137, C0105:L137, C0121:L137, C0122:L137, C0123:L154, C0124:L153, C0143:L137, C0144:L137, C0145:L154, C0146:L153.

## catalogue_mgcp — captured_unmapped — 8 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0014:L124, C0015:L122, C0016:L105, C0017:L106, C0019:L206, C0020:L163, C0021:L191, C0022:L152.

## catalogue_mmi_no_auto — captured_unmapped — 35 occurrences

Décision : NEEDS_REVIEW ; priorité : P1. Sémantique/source non établie : maintien natif selon la décision initiale.

Preuves : C0031:L30, C0032:L25, C0033:L25, C0034:L25, C0044:L30, C0045:L30, C0089:L30, C0090:L30, C0106:L27, C0107:L27, C0108:L27, C0109:L27, C0116:L25, C0117:L25, C0118:L25, C0119:L25, C0125:L30, C0126:L30, C0127:L30, C0128:L30, C0138:L25, C0139:L25, C0140:L25, C0141:L25, C0148:L25, C0149:L25, C0150:L25, C0151:L30, C0152:L30, C0153:L30, C0154:L30, C0160:L30, C0161:L30, C0162:L30, C0163:L30.

## catalogue_mmi_no_pvc — captured_unmapped — 35 occurrences

Décision : NEEDS_REVIEW ; priorité : P2. Sémantique/source non établie : maintien natif selon la décision initiale.

Preuves : C0031:L31, C0032:L26, C0033:L26, C0034:L26, C0044:L31, C0045:L31, C0089:L31, C0090:L31, C0106:L28, C0107:L28, C0108:L28, C0109:L28, C0116:L26, C0117:L26, C0118:L26, C0119:L26, C0125:L31, C0126:L31, C0127:L31, C0128:L31, C0138:L26, C0139:L26, C0140:L26, C0141:L26, C0148:L26, C0149:L26, C0150:L26, C0151:L31, C0152:L31, C0153:L31, C0154:L31, C0160:L31, C0161:L31, C0162:L31, C0163:L31.

## catalogue_mmi_poll — captured_unmapped — 35 occurrences

Décision : NEEDS_REVIEW ; priorité : P2. Sémantique/source non établie : maintien natif selon la décision initiale.

Preuves : C0031:L29, C0032:L24, C0033:L24, C0034:L24, C0044:L29, C0045:L29, C0089:L29, C0090:L29, C0106:L26, C0107:L26, C0108:L26, C0109:L26, C0116:L24, C0117:L24, C0118:L24, C0119:L24, C0125:L29, C0126:L29, C0127:L29, C0128:L29, C0138:L24, C0139:L24, C0140:L24, C0141:L24, C0148:L24, C0149:L24, C0150:L24, C0151:L29, C0152:L29, C0153:L29, C0154:L29, C0160:L29, C0161:L29, C0162:L29, C0163:L29.

## catalogue_mmi_timeout — captured_unmapped — 35 occurrences

Décision : NEEDS_REVIEW ; priorité : P2. Sémantique/source non établie : maintien natif selon la décision initiale.

Preuves : C0031:L32, C0032:L27, C0033:L27, C0034:L27, C0044:L32, C0045:L32, C0089:L32, C0090:L32, C0106:L29, C0107:L29, C0108:L29, C0109:L29, C0116:L27, C0117:L27, C0118:L27, C0119:L27, C0125:L32, C0126:L32, C0127:L32, C0128:L32, C0138:L27, C0139:L27, C0140:L27, C0141:L27, C0148:L27, C0149:L27, C0150:L27, C0151:L32, C0152:L32, C0153:L32, C0154:L32, C0160:L32, C0161:L32, C0162:L32, C0163:L32.

## catalogue_msdp_cache — captured_unmapped — 1 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0043:L231.

## catalogue_multilink — captured_unmapped — 85 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0001:L28, C0002:L31, C0003:L31, C0004:L33, C0005:L30, C0006:L31, C0007:L28, C0008:L28, C0009:L28, C0010:L31, C0011:L31, C0012:L31, C0014:L32, C0015:L33, C0016:L32, C0017:L32, C0019:L40, C0020:L40, C0021:L32, C0022:L33, C0024:L47, C0025:L47, C0026:L47, C0027:L47, C0028:L47, C0029:L47, C0030:L47, C0031:L50, C0032:L45, C0033:L45, C0034:L45, C0042:L48, C0043:L50, C0044:L48, C0045:L48, C0064:L36, C0065:L36, C0066:L36, C0068:L50, C0069:L50, C0070:L51, C0071:L50, C0075:L48, C0076:L48, C0077:L48, C0089:L48, C0090:L48, C0103:L49, C0104:L49, C0105:L49, C0106:L45, C0107:L45, C0108:L45, C0109:L45, C0116:L43, C0117:L43, C0118:L43, C0119:L43, C0121:L49, C0122:L49, C0123:L66, C0124:L65, C0125:L48, C0126:L48, C0127:L48, C0128:L48, C0138:L43, C0139:L43, C0140:L43, C0141:L43, C0143:L49, C0144:L49, C0145:L66, C0146:L65, C0148:L43, C0149:L43, C0150:L43, C0151:L48, C0152:L48, C0153:L48, C0154:L48, C0160:L48, C0161:L48, C0162:L48, C0163:L48.

## catalogue_no_cdp_log — captured_unmapped — 12 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0014:L116, C0015:L114, C0016:L97, C0017:L98, C0019:L192, C0020:L149, C0021:L174, C0022:L135, C0031:L59, C0032:L54, C0033:L54, C0034:L54.

## catalogue_no_punt — captured_unmapped — 7 occurrences

Décision : KEEP_NATIVE ; priorité : P2. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0024:L10, C0025:L10, C0026:L10, C0027:L10, C0028:L10, C0029:L10, C0030:L10.

## catalogue_punt — captured_unmapped — 18 occurrences

Décision : KEEP_NATIVE ; priorité : P2. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0068:L13, C0069:L13, C0070:L13, C0071:L13, C0075:L11, C0076:L11, C0077:L11, C0103:L12, C0104:L12, C0105:L12, C0121:L12, C0122:L12, C0123:L12, C0124:L12, C0143:L12, C0144:L12, C0145:L12, C0146:L12.

## catalogue_qfp — captured_unmapped — 18 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0068:L12, C0069:L12, C0070:L12, C0071:L12, C0075:L10, C0076:L10, C0077:L10, C0103:L11, C0104:L11, C0105:L11, C0121:L11, C0122:L11, C0123:L11, C0124:L11, C0143:L11, C0144:L11, C0145:L11, C0146:L11.

## catalogue_redundancy — captured_unmapped — 71 occurrences

Décision : KEEP_NATIVE ; priorité : P2. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0014:L43, C0015:L44, C0016:L43, C0017:L43, C0019:L52, C0020:L51, C0021:L43, C0022:L44, C0024:L106, C0025:L113, C0026:L106, C0027:L106, C0028:L106, C0029:L106, C0030:L106, C0031:L57, C0032:L52, C0033:L52, C0034:L52, C0044:L55, C0045:L55, C0064:L95, C0065:L95, C0066:L95, C0068:L144, C0069:L144, C0070:L145, C0071:L144, C0075:L148, C0076:L148, C0077:L148, C0089:L55, C0090:L55, C0103:L143, C0104:L143, C0105:L143, C0106:L51, C0107:L51, C0108:L51, C0109:L51, C0116:L49, C0117:L49, C0118:L49, C0119:L49, C0121:L143, C0122:L143, C0123:L160, C0124:L159, C0125:L55, C0126:L55, C0127:L55, C0128:L55, C0138:L49, C0139:L49, C0140:L49, C0141:L49, C0143:L143, C0144:L143, C0145:L160, C0146:L159, C0148:L49, C0149:L49, C0150:L49, C0151:L55, C0152:L55, C0153:L55, C0154:L55, C0160:L55, C0161:L55, C0162:L55, C0163:L55.

## catalogue_scheduler — captured_unmapped — 2 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0042:L289, C0043:L358.

## catalogue_scheduler_none — captured_unmapped — 35 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0031:L160, C0032:L165, C0033:L164, C0034:L165, C0044:L156, C0045:L156, C0089:L155, C0090:L155, C0106:L128, C0107:L128, C0108:L129, C0109:L128, C0116:L154, C0117:L154, C0118:L154, C0119:L154, C0125:L160, C0126:L160, C0127:L160, C0128:L160, C0138:L153, C0139:L153, C0140:L153, C0141:L153, C0148:L160, C0149:L158, C0150:L158, C0151:L164, C0152:L164, C0153:L164, C0154:L164, C0160:L165, C0161:L165, C0162:L165, C0163:L165.

## catalogue_soft — captured_unmapped — 1 occurrences

Décision : EXTEND_MODEL ; priorité : P2. P2 différé explicitement par la mission. Seule identité du cache parent utilisée si indispensable au collecteur P1.

Preuves : C0032:L105.

## catalogue_spanning_system_id — captured_unmapped — 28 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0024:L101, C0025:L108, C0026:L101, C0027:L101, C0028:L101, C0029:L101, C0030:L101, C0064:L92, C0065:L92, C0066:L92, C0068:L141, C0069:L141, C0070:L142, C0071:L141, C0075:L145, C0076:L145, C0077:L145, C0103:L140, C0104:L140, C0105:L140, C0121:L140, C0122:L140, C0123:L157, C0124:L156, C0143:L140, C0144:L140, C0145:L157, C0146:L156.

## catalogue_subscriber — captured_unmapped — 28 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0024:L43, C0025:L43, C0026:L43, C0027:L43, C0028:L43, C0029:L43, C0030:L43, C0064:L29, C0065:L29, C0066:L29, C0068:L43, C0069:L43, C0070:L44, C0071:L43, C0075:L41, C0076:L41, C0077:L41, C0103:L42, C0104:L42, C0105:L42, C0121:L42, C0122:L42, C0123:L59, C0124:L58, C0143:L42, C0144:L42, C0145:L59, C0146:L58.

## catalogue_upgrade — captured_unmapped — 8 occurrences

Décision : KEEP_NATIVE ; priorité : P3. Conservation native suffisante dans le profil courant ; ne vaut pas normalisation complète.

Preuves : C0014:L6, C0015:L7, C0016:L6, C0017:L6, C0019:L6, C0020:L6, C0021:L6, C0022:L7.

## policy_match_community — captured_unmapped — 16 occurrences

Décision : MAP_EXISTING ; priorité : P1. Référence de communauté conservée, mais dépendance de regex Cisco non validée. Pas de promotion automatique.

Preuves : C0001:L154, C0001:L168, C0002:L153, C0002:L167, C0002:L176, C0004:L160, C0004:L175, C0005:L156, C0005:L171, C0007:L134, C0008:L128, C0009:L128, C0010:L143, C0010:L162, C0011:L141, C0011:L155.

## services_aaa_method — captured_unmapped — 1 occurrences

Décision : NEEDS_REVIEW ; priorité : P1. Sémantique/source non établie : maintien natif selon la décision initiale.

Preuves : C0004:L31.

## services_aaa_off — captured_unmapped — 1 occurrences

Décision : NEEDS_REVIEW ; priorité : P1. Sémantique/source non établie : maintien natif selon la décision initiale.

Preuves : C0004:L17.

## services_community_expanded — partially_normalized — 22 occurrences

Décision : hors captures natives initiales ; priorité : statut préservé. Expression Cisco non entièrement validée.

Preuves : C0001:L119, C0001:L120, C0001:L121, C0002:L123, C0002:L124, C0002:L125, C0002:L126, C0004:L123, C0004:L124, C0004:L125, C0005:L120, C0005:L121, C0005:L122, C0007:L107, C0008:L111, C0009:L111, C0010:L113, C0010:L114, C0010:L115, C0011:L113, C0011:L114, C0011:L115.

## sans règle : logging synchronous global — unrecognized — 3 occurrences

Décision : hors captures natives initiales ; priorité : statut préservé. Commande globale sans contexte line valide.

Preuves : C0107:L122, C0108:L123, C0109:L122.
