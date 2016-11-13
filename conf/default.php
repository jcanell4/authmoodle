<?php

$conf['charset']        = 'utf8';
$conf['debug']          = 0;
$conf['TablesToLock']   = array('mdl_user');

$conf['server']         = 'localhost';   
$conf['serverUser']     = 'localhost';   
$conf['serverGroup']    = 'localhost';  
$conf['user']           = 'root';
$conf['password']       = 'momo';      
$conf['forwardClearPass'] = 0;
$conf['database']       = 'moodle2';
$conf['databaseUser']   = 'moodle2';
$conf['databaseGroup']  = 'wikiioc';

$conf['checkPass']      = 'SELECT password AS pass FROM mdl_user WHERE username=\'%{user}\' AND mnethostid=1 AND deleted=0';
$conf['getUserInfo']    = 'SELECT password AS pass, TRIM(CONCAT(firstname, \' \', lastname)) AS name, email AS mail FROM mdl_user WHERE username=\'%{user}\' AND mnethostid=1 AND deleted=0';
$conf['getUsers']       = 'SELECT DISTINCT username AS user FROM mdl_user WHERE mnethostid=1 AND deleted=0';
$conf['getUserID']      = 'SELECT id FROM mdl_user WHERE username=\'%{user}\' AND mnethostid=1 AND deleted=0';
$conf['FilterLogin']    = 'username LIKE \'%{user}\'';
$conf['FilterName']     = 'TRIM(CONCAT(firstname, \' \', lastname)) LIKE \'%{name}\'';
$conf['FilterEmail']    = 'email LIKE \'%{email}\'';
$conf['SortOrder']      = 'ORDER BY username';
$conf['updateUser']     = 'UPDATE mdl_user SET';
$conf['UpdateLogin']    = 'username=\'%{user}\'';
$conf['UpdatePass']     = 'password=\'%{pass}\'';
$conf['UpdateEmail']    = 'email=\'%{email}\'';
$conf['UpdateName']     = 'firstname=SUBSTRING_INDEX(\'%{name}\',\' \',1), lastname=SUBSTRING_INDEX(\'%{name}\',\' \',-1)';
$conf['UpdateTarget']   = 'WHERE id=\'%{uid}\'';
$conf['addUser']        = 'INSERT INTO mdl_user (mnethostid,username,password,firstname,lastname,email) VALUES (1, \'%{user}\', \'%{pass}\', SUBSTRING_INDEX(\'%{name}\',\' \',1), SUBSTRING_INDEX(\'%{name}\',\' \',-1), \'%{email}\')';
$conf['delUser']        = 'DELETE FROM mdl_user WHERE id=\'%{uid}\' AND username=\'%{user}\'';
$conf['delUserRefs']    = 'DELETE FROM mdl_user WHERE id=\'%{uid}\'';

$conf['FilterGroup']    = 'TRUE';
$conf['defaultgroup']   = 'user';
$conf['getGroups']      = 'SELECT g.name AS groupname FROM wiki_group AS g JOIN wiki_user_group AS u ON (u.id_group=g.id) WHERE u.id_user=\'%{uid}\'';
$conf['getGroupID']     = 'SELECT id FROM wiki_group WHERE name=\'%{group}\'';
$conf['addGroup']       = 'INSERT INTO wiki_group (name) VALUES (\'%{group}\')';
$conf['addUserGroup']   = 'INSERT INTO wiki_user_group (id_user, id_group) VALUES (\'%{uid}\', \'%{gid}\')';
$conf['delGroup']       = 'DELETE FROM wiki_group WHERE id=\'%{gid}\' AND name=\'%{group}\'';
$conf['delUserGroup']   = 'DELETE FROM wiki_user_group WHERE id_user=\'%{uid}\'';
