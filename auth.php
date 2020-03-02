<?php
if(!defined('DOKU_INC')) die();
/**
 * Moodle authentication backend
 *
 * This plugin is based on Andreas Gohr's authmysql
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @culpable   Rafael Claver
 */
class auth_plugin_authmoodle extends DokuWiki_Auth_Plugin {
    protected $dbcon = 0;       // conexión actual
    protected $dbconUser = 0;   // conexión para la base de datos moodle para la tabla mdl_user
    protected $dbconGroup = 0;  // conexión para la base de datos wikiioc para la tabla mdl_groups
    protected $dbver = 0;   // @var int database version
    protected $dbrev = 0;   // @var int database revision
    protected $dbsub = 0;   // @var int database subrevision
    protected $moodleToken="";

    /**
     * Constructor
     *
     * checks if the mysql interface is available, otherwise it will
     * set the variable $success of the basis class to false
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    public function __construct() {
        parent::__construct();
        $this->cando['modMoodle'] = false;

        if(!function_exists('mysqli_connect')) {
            $this->_debug("MySQL err: PHP MySQL extension not found.", -1, __LINE__, __FILE__);
            $this->success = false;
            return;
        }

        // set capabilities based upon config strings set
        if(!$this->getConf('server') || !$this->getConf('user') || !$this->getConf('database')) {
            $this->_debug("MySQL err: insufficient configuration.", -1, __LINE__, __FILE__);

            $this->success = false;
            return;
        }

        $this->cando['addUser']   = $this->_chkcnf(
            array(
                 'getUserInfo',
                 'getGroups',
                 'addUser',
                 'getUserID',
                 'getGroupID',
                 'addGroup',
                 'addUserGroup'
            ), true
        );
        $this->cando['delUser']   = $this->_chkcnf(
            array(
                 'getUserID',
                 'delUser',
                 'delUserRefs',
                 'delUserRelGroup'
            ), true
        );
        $this->cando['modLogin']  = $this->_chkcnf(
            array(
                 'getUserID',
                 'updateUser',
                 'UpdateTarget'
            ), true
        );
        $this->cando['modPass']   = $this->cando['modLogin'];
        $this->cando['modName']   = $this->cando['modLogin'];
        $this->cando['modMail']   = $this->cando['modLogin'];
        $this->cando['modMoodle'] = $this->cando['modLogin'];
        $this->cando['modEditor'] = $this->cando['modLogin'];
        $this->cando['modGroups'] = $this->_chkcnf(
            array(
                 'getUserID',
                 'getGroups',
                 'getGroupID',
                 'addGroup',
                 'addUserGroup',
                 'delGroup',
                 'getGroupID',
                 'delUserGroup',
                 'delUserRelGroup'
            ), true
        );
        /* getGroups is not yet supported
           $this->cando['getGroups']    = $this->_chkcnf(
                array(
                    'getGroups',
                    'getGroupID'
                ), false);
         */
        $this->cando['getUsers']     = $this->_chkcnf(
            array(
                 'getUsers',
                 'getUserInfo',
                 'getGroups'
            ), false
        );
        $this->cando['getUserCount'] = $this->_chkcnf(array('getUsers'), false);

        if($this->getConf('debug') >= 2) {
            $candoDebug = '';
            foreach($this->cando as $cd => $value) {
                if($value) { $value = 'yes'; } else { $value = 'no'; }
                $candoDebug .= $cd . ": " . $value . " | ";
            }
            $this->_debug("authmoodle cando: " . $candoDebug, 0, __LINE__, __FILE__);
        }
    }

    public function getMoodleToken(){
        return $this->moodleToken;
    }

    public function hasMoodleToken(){
        return !empty($this->moodleToken);
    }

    /**
     * Check if the given config strings are set
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     * @param   array $keys
     * @param   bool  $wop is this a check for a write operation?
     * @return  bool
     */
    protected function _chkcnf($keys, $wop = false) {
        foreach($keys as $key) {
            if(!$this->getConf($key)) return false;
        }

        /* write operation and lock array filled with tables names? */
        if ($wop && (!is_array($this->getConf('TablesToLock')) || !count($this->getConf('TablesToLock'))) ) {
            return false;
        }

        return true;
    }

    /**
     * @Overwrite
     * @param type $cap
     * @return boolean
     */
    public function canDo($cap) {
        $ret = parent::canDo($cap);
        if ($cap === 'UserMod')
            $ret = $ret || $this->cando['modMoodle'];
        return $ret;
    }

    /**
     * Comproba si l'usuari existeix a la base de dades de la wiki;
     * si existeix, comproba si s'ha de validar contra la base de dades de moodle
     * o directament contra la base de dades de la wiki
     *
     * @param  string $user user who would like access
     * @param  string $pass user's clear text password to check
     * @return bool
     */
    public function checkPass($user, $pass) {
        $rc = false;
        $info = $this->getUserData($user);
        if ($info) {
            if ($info['moodle']) {
                $ws = new WsMoodleClient();
                $ws->updateToken($user, $pass);
                $this->moodleToken = $ws->getToken();
                $rc = !empty($ws->getToken());
            }else {
                $rc = $this->_checkPass($user, $pass);
            }
        }
        return $rc;
    }

    /**
     * Checks if the given user exists and the given plaintext password
     * is correct. Furtheron it might be checked wether the user is
     * member of the right group
     *
     * Depending on which SQL string is defined in the config, password
     * checking is done here (getpass) or by the database (passcheck)
     *
     * @param  string $user user who would like access
     * @param  string $pass user's clear text password to check
     * @return bool
     */
    private function _checkPass($user, $pass) {
        global $conf;
        $rc = false;

        if($this->_openDB()) {
            $sql = $this->getConf('checkPass');
            $this->dbcon = (strpos("wiki_group", $sql) !== FALSE) ? $this->dbconGroup : $this->dbconUser;
            $sql    = str_replace('%{user}', $this->_escape($user), $sql);
            $sql    = str_replace('%{pass}', $this->_escape($pass), $sql);
            $sql    = str_replace('%{dgroup}', $this->_escape($conf['defaultgroup']), $sql);
            $this->_debug('MySQL query: '.hsc($sql), 0, __LINE__, __FILE__, 2);
            $result = $this->_queryDB($sql);

            if($result !== false && count($result) == 1) {
                $this->_debug('MySQL result: OK', 0, __LINE__, __FILE__, 2);
                if($this->getConf('forwardClearPass') == 1) {
                    $rc = true;
                } else {
                    if (!function_exists('crypt')) {
                        return false;
                    }
                    $hash = $result[0]['pass'];
                    $ret = crypt($pass, $hash);
                    if (!is_string($ret) || strlen($ret) != strlen($hash) || strlen($ret) <= 13) {
                        return false;
                    }

                    $status = 0;
                    for ($i = 0; $i < strlen($ret); $i++) {
                        $status |= (ord($ret[$i]) ^ ord($hash[$i]));
                    }
                    $rc = ($status === 0);
                }
            }else{
                $this->_debug('MySQL result: FALSE', 0, __LINE__, __FILE__, 2);
            }
            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * Return user info
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param string $user user login to get data for
     * @return array|bool
     */
    public function getUserData($user) {
        if($this->_openDB()) {
            $this->_lockTables("READ");
            $info = $this->_getUserInfo($user);
            $this->_unlockTables();
            $this->_closeDB();
        } else
            $info = false;
        return $info;
    }

    /**
     * Create a new User. Returns false if the user already exists,
     * null when an error occurred and true if everything went well.
     *
     * The new user will be added to the default group by this
     * function if grps are not specified (default behaviour).
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param string $user  nick of the user
     * @param string $pwd   clear text password
     * @param string $name  full name of the user
     * @param string $mail  email address
     * @param string $moodle as user account in moodle?
     * @param string $editor editor utilizado por el usuario
     * @param array  $grps  array of groups the user should become member of
     * @return bool|null
     */
    public function createUser($user, $pwd, $name, $mail, $moodle, $editor, $grps = null) {
        global $conf;

        if ($this->_openDB()) {
            if (($info = $this->_getUserInfo($user)) !== false)
                return false; // user already exists

            // set defaultgroup if no groups were given
            if ($grps == null)
                $grps = array($conf['defaultgroup']);

            $this->_lockTables("WRITE");
            $pwd = $this->getConf('forwardClearPass') ? $pwd : auth_cryptPassword($pwd);
            $rc  = $this->_addUser($user, $pwd, $name, $mail, $moodle, $editor, $grps);
            $this->_unlockTables();
            $this->_closeDB();
            if($rc) return true;
        }
        return null; // return error
    }

    /**
     * Modify user data
     *
     * An existing user dataset will be modified. Changes are given in an array.
     *
     * The dataset update will be rejected if the user name should be changed
     * to an already existing one.
     *
     * The password must be provides unencrypted. Pasword cryption is done
     * automatically if configured.
     *
     * If one or more groups could't be updated, an error would be set. In
     * this case the dataset might already be changed and we can't rollback
     * the changes. Transactions would be really usefull here.
     *
     * modifyUser() may be called without SQL statements defined that are
     * needed to change group membership (for example if only the user profile
     * should be modified). In this case we asure that we don't touch groups
     * even $changes['grps'] is set by mistake.
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user    nick of the user to be changed
     * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
     * @return  bool   true on success, false on error
     */
    public function modifyUser($user, $changes) {
        $rc = false;

        if(!is_array($changes) || !count($changes))
            return true; // nothing to change

        if($this->_openDB()) {
            $this->_lockTables("WRITE");

            if(($uid = $this->_getUserID($user))) {
                $rc = $this->_updateUserInfo($changes, $uid, $changes['ignoreNull']);

                if ($rc && isset($changes['grps']) && $this->cando['modGroups']) {
                    $groups = $this->_getGroups($user);
                    $grpadd = array_diff($changes['grps'], $groups);
                    if (! $changes['onlyAddGroup'])
                        $grpdel = array_diff($groups, $changes['grps']);

                    if ($grpdel) {
                        foreach($grpdel as $group)
                            $rc = $rc && $this->_delUserFromGroup($user, $group);
                    }

                    if ($grpadd) {
                        foreach($grpadd as $group)
                            $rc = $rc && $this->_addUserToGroup($user, $group, 1);
                    }
                }

                if ($rc && isset($changes['delgrps']) && $this->cando['modGroups']) {
                    foreach($changes['delgrps'] as $group)
                        $rc = $rc && $this->_delUserFromGroup($user, $group);
                }
            }
            $this->_unlockTables();
            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * [public function]
     *
     * Remove one or more users from the list of registered users
     *
     * @param   array  $users   array of users to be deleted
     * @return  int             the number of users deleted
     *
     * @author  Christopher Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    function deleteUsers($users) {
        $count = 0;

        if($this->_openDB()) {
            if(is_array($users) && count($users)) {
                $this->_lockTables("WRITE");
                foreach($users as $user) {
                    if($this->_delUser($user))
                        $count++;
                }
                $this->_unlockTables();
            }
            $this->_closeDB();
        }
        return $count;
    }

    /**
     * Counts users which meet certain $filter criteria.
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  array $filter  filter criteria in item/pattern pairs
     * @return int count of found users
     */
    public function getUserCount($filter = array()) {
        $rc = 0;

        if($this->_openDB()) {
            $sql = $this->_createSQLFilter($this->getConf('getUsers'), $filter);

            if($this->dbver >= 4) {
                $sql = substr($sql, 6); /* remove 'SELECT' or 'select' */
                $sql = "SELECT SQL_CALC_FOUND_ROWS".$sql." LIMIT 1";
                $this->_queryDB($sql);
                $result = $this->_queryDB("SELECT FOUND_ROWS()");
                $rc     = $result[0]['FOUND_ROWS()'];
            } else if(($result = $this->_queryDB($sql)))
                $rc = count($result);

            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * Bulk retrieval of user data
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  int          $first  index of first user to be returned
     * @param  int          $limit  max number of users to be returned; 0 para recuperar todas las filas
     * @param  array|string $filter array of field/pattern pairs
     * @return  array userinfo (refer getUserData for internal userinfo details)
     */
    public function retrieveUsers($first = 0, $limit = 10, $filter = array()) {
        $out = array();

        if ($this->_openDB()) {
            $this->dbcon = $this->dbconUser;
            $this->_lockTables("READ");
            $sql = $this->_createSQLFilter($this->getConf('getUsers'), $filter);
            $sql .= " ".$this->getConf('SortOrder');
            if ($limit > 0) //$limit=0 para recuperar todas las filas
                $sql .= " LIMIT $first, $limit";
            $result = $this->_queryDB($sql);

            if (!empty($result)) {
                foreach($result as $user)
                    if (($info = $this->_getUserInfo($user['user'])))
                        $out[$user['user']] = $info;
            }

            $this->_unlockTables();
            $this->_closeDB();
        }
        return $out;
    }

    /**
     * Give user membership of a group
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user
     * @param   string $group
     * @return  bool   true on success, false on error
     */
    protected function joinGroup($user, $group) {
        $rc = false;

        if($this->_openDB()) {
            $this->_lockTables("WRITE");
            $rc = $this->_addUserToGroup($user, $group);
            $this->_unlockTables();
            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * Remove user from a group
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user  user that leaves a group
     * @param   string $group group to leave
     * @return  bool
     */
    protected function leaveGroup($user, $group) {
        $rc = false;

        if($this->_openDB()) {
            $this->_lockTables("WRITE");
            $rc  = $this->_delUserFromGroup($user, $group);
            $this->_unlockTables();
            $this->_closeDB();
        }
        return $rc;
    }

    /**
     * MySQL is case-insensitive
     */
    public function isCaseSensitive() {
        return false;
    }

    /**
     * Adds a user to a group.
     *
     * If $force is set to true non existing groups would be created.
     *
     * The database connection must already be established. Otherwise
     * this function does nothing and returns 'false'. It is strongly
     * recommended to call this function only after all participating
     * tables (group and usergroup) have been locked.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user    user to add to a group
     * @param   string $group   name of the group
     * @param   bool   $force   create missing groups
     * @return  bool   true on success, false on error
     */
    protected function _addUserToGroup($user, $group, $force = false) {
        $newgroup = 0;

        if (($this->dbconGroup) && $this->dbconUser && ($user)) {
            $gid = $this->_getGroupID($group);
            if (!$gid) {
                if ($force) { // create missing groups
                    $sql      = str_replace('%{group}', $this->_escape($group,TRUE), $this->getConf('addGroup'));
                    $gid      = $this->_modifyDB($sql);
                    $newgroup = 1; // group newly created
                }
                if (!$gid) return false; // group didn't exist and can't be created
            }

            $sql = $this->getConf('addUserGroup');
            $uid = $this->_getUserID($user);
            $sql = str_replace('%{uid}', $this->_escape($uid), $sql);

            $sql = str_replace('%{gid}', $this->_escape($gid), $sql);
            $result = $this->_modifyDB($sql);
            if ($result !== false)
                return true;

            if ($newgroup) { // remove previously created group on error
                $sql = str_replace('%{gid}', $this->_escape($gid), $this->getConf('delGroup'));
                $sql = str_replace('%{group}', $this->_escape($group,TRUE), $sql);
                $this->_modifyDB($sql);
            }
        }
        return false;
    }

    /**
     * Remove user from a group
     *
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param   string $user  user that leaves a group
     * @param   string $group group to leave
     * @return  bool   true on success, false on error
     */
    protected function _delUserFromGroup($user, $group) {
        $rc = false;

        $this->dbcon = $this->dbconGroup;
        if (($this->dbcon) && ($user)) {
            $sql = $this->getConf('delUserGroup');
            if (strpos($sql, '%{uid}') !== false) {
                $uid = $this->_getUserID($user);
                $sql = str_replace('%{uid}', $this->_escape($uid), $sql);
            }
            $gid = $this->_getGroupID($group);
            if ($gid) {
                $sql = str_replace('%{user}', $this->_escape($user), $sql);
                $sql = str_replace('%{gid}', $this->_escape($gid), $sql);
                $sql = str_replace('%{group}', $this->_escape($group,TRUE), $sql);
                $rc  = $this->_modifyDB($sql) == 0 ? true : false;
            }
        }
        return $rc;
    }

    /**
     * Retrieves a list of groups the user is a member off.
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user user whose groups should be listed
     * @return bool|array false on error, all groups on success
     */
    protected function _getGroups($user) {
        $groups = array();

        if ($this->dbcon) {
            $sql = $this->getConf('getGroups');
            if (strpos($sql, '%{uid}') !== false) {
                $uid = $this->_getUserID($user);
                $sql = str_replace('%{uid}', $this->_escape($uid), $sql);

                $result = $this->_queryDB($sql);

                if ($result !== false && count($result)) {
                    foreach($result as $row)
                        $groups[] = $row['groupname'];
                }
                return $groups;
            }
        }
        return false;
    }

    /**
     * Retrieves the user id of a given user name
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user user whose id is desired
     * @return mixed  user id
     */
    protected function _getUserID($user) {
        $this->dbcon = $this->dbconUser;
        if ($this->dbcon) {
            $sql    = str_replace('%{user}', $this->_escape($user), $this->getConf('getUserID'));
            $result = $this->_queryDB($sql);
            return ($result === false) ? false : $result[0]['id'];
        }
        return false;
    }

    /**
     * Adds a new User to the database.
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user  login of the user
     * @param  string $pwd   encrypted password
     * @param  string $name  full name of the user
     * @param  string $mail  email address
     * @param  string $moodle as user account in moodle?
     * @param  string $editor editor utilizado por el usuario
     * @param  array  $grps  array of groups the user should become member of
     * @return bool
     */
    protected function _addUser($user, $pwd, $name, $mail, $moodle, $editor, $grps) {
        if ($this->dbcon && is_array($grps)) {
            $this->dbcon = $this->dbconUser;
            $sql = str_replace('%{user}', $this->_escape($user), $this->getConf('addUser'));
            $sql = str_replace('%{pass}', $this->_escape($pwd), $sql);
            $name = $this->_escape($name);
            $aname = explode(",", $name);
            if (isset($aname[1])) {
                $firstname = $aname[1];
                $lastname = $aname[0];
            }else {
                $aname = explode(" ", $name, 2);
                $firstname = $aname[0];
                $lastname = isset($aname[1]) ? $aname[1] : "";
            }
            $sql = str_replace('%{firstname}', $firstname, $sql);
            $sql = str_replace('%{lastname}', $lastname, $sql);
            $sql = str_replace('%{email}', $this->_escape($mail), $sql);
            $sql = str_replace('%{moodle}', $this->_escape($moodle), $sql);
            $sql = str_replace('%{editor}', $this->_escape($editor), $sql);
            $uid = $this->_modifyDB($sql);
            $gid = false;
            $group = '';

            if ($uid) {
                foreach($grps as $group) {
                    $gid = $this->_addUserToGroup($user, $group, 1);
                    if ($gid === false) break;
                }

                if ($gid !== false){
                    return true;
                } else {
                    /* remove the new user and all group relations if a group can't
                     * be assigned. Newly created groups will remain in the database
                     * and won't be removed. This might create orphaned groups but
                     * is not a big issue so we ignore this problem here.
                     */
                    $this->_delUser($user);
                    $this->_debug("MySQL err: Adding user '$user' to group '$group' failed.", -1, __LINE__, __FILE__);
                }
            }
        }
        return false;
    }

    /**
     * Deletes a given user and all his group references.
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user user whose id is desired
     * @return bool
     */
    protected function _delUser($user) {
        if ($this->dbcon) {
            $this->dbcon = $this->dbconUser;
            $uid = $this->_getUserID($user);
            if ($uid) {
                $sql = str_replace('%{uid}', $this->_escape($uid), $this->getConf('delUserRefs'));
                $ret = ($this->_modifyDB($sql)===0) ? true : false;
                if ($ret) {
                    $this->dbcon = $this->dbconGroup;
                    $sql = str_replace('%{uid}', $this->_escape($uid), $this->getConf('delUserRelGroup'));
                    $ret  = ($this->_modifyDB($sql) == 0) ? true : false;
                }
            }
        }
        return $ret;
    }

    /**
     * getUserInfo
     *
     * Gets the data for a specific user The database connection
     * must already be established for this function to work.
     * Otherwise it will return 'false'.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $user  user's nick to get data for
     * @return bool|array false on error, user info on success
     */
    protected function _getUserInfo($user) {
        $this->dbcon = $this->dbconUser;
        if ($this->dbcon) {
            $sql    = str_replace('%{user}', $this->_escape($user), $this->getConf('getUserInfo'));
            $result = $this->_queryDB($sql);
            if ($result !== false && count($result)) {
                $info         = $result[0];
                $info['grps'] = $this->_getGroups($user);
                return $info;
            }
        }
        return false;
    }

    /**
     * Updates the user info in the database
     *
     * Update a user data structure in the database according changes
     * given in an array. The user name can only be changes if it didn't
     * exists already. If the new user name exists the update procedure
     * will be aborted. The database keeps unchanged.
     *
     * The database connection has already to be established for this
     * function to work. Otherwise it will return 'false'.
     *
     * The password will be crypted if necessary.
     *
     * @param array $changes array of items to change as pairs of item and value
     * @param mixed $uid     user id of dataset to change, must be unique in DB
     * @param string $ignoreNull  TRUE=No actualizará con valores vacíos (borrar datos)
     * @return bool true on success or false on error
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    protected function _updateUserInfo($changes, $uid, $ignoreNull=FALSE) {
        $sql = $this->getConf('updateUser')." ";
        $cnt = 0;
        $err = 0;

        $this->dbcon = $this->dbconUser;
        if ($this->dbcon) {
            foreach($changes as $item => $value) {
                if (!empty($value) || !$ignoreNull) {
                    switch ($item) {
                        case 'user':
                            if(($this->_getUserID($changes['user']))) {
                                $err = 1; /* new username already exists */
                                break 2; /* abort update */
                            }
                            if ($cnt++ > 0) $sql .= ", ";
                            $sql .= str_replace('%{user}', $value, $this->getConf('UpdateLogin'));
                            break;
                        case 'name':
                            if ($cnt++ > 0) $sql .= ", ";
                            //$sql .= str_replace('%{name}',$value,$this->cnf['UpdateName']); ANTIGUA VERSIÓN
                            $name = explode(" ", $value, 2);
                            $sql .= str_replace('%{firstname}', trim($name[0]), $this->getConf('UpdateName'));
                            $sql = str_replace('%{lastname}', trim($name[1]), $sql);
                            break;
                        case 'pass':
                            if (!$this->getConf('forwardClearPass'))
                                $value = auth_cryptPassword($value);
                            if ($cnt++ > 0) $sql .= ", ";
                            $sql .= str_replace('%{pass}', $value, $this->getConf('UpdatePass'));
                            break;
                        case 'mail':
                            if ($cnt++ > 0) $sql .= ", ";
                            $sql .= str_replace('%{email}', $value, $this->getConf('UpdateEmail'));
                            break;
                        case 'moodle':
                            if ($cnt++ > 0) $sql .= ", ";
                            $sql .= str_replace('%{moodle}', $value, $this->getConf('UpdateMoodle'));
                            break;
                        case 'editor':
                            if ($cnt++ > 0) $sql .= ", ";
                            $sql .= str_replace('%{editor}', $value, $this->getConf('UpdateEditor'));
                            break;
                    }
                }
            }

            if($err == 0) {
                if($cnt > 0) {
                    $sql .= " ".str_replace('%{uid}', $uid, $this->getConf('UpdateTarget'));
                    if(get_class($this) == 'auth_mysql') $sql .= " LIMIT 1"; //some PgSQL inheritance comp.
                    $this->_modifyDB($sql);
                }
                return true;
            }
        }
        return false;
    }

    /**
     * Retrieves the group id of a given group name
     *
     * The database connection must already be established
     * for this function to work. Otherwise it will return
     * false.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $group   group name which id is desired
     * @return mixed group id
     */
    protected function _getGroupID($group) {
        $this->dbcon = $this->dbconGroup;
        if ($this->dbcon) {
            $sql    = str_replace('%{group}', $this->_escape($group,TRUE), $this->getConf('getGroupID'));
            $result = $this->_queryDB($sql);
            return $result === false ? false : $result[0]['id'];
        }
        return false;
    }

    /**
     * Se utilizan 2 conexiones independientes, una para cada base de datos dado que
     * la tabla mdl_user está en la base de datos moodle gestionada por una empresa privada
     * y la tabla mdl_groups está en una base de datos local wikiioc
     * @culpable Rafael Claver
     * @return bool
     */
    protected function _openDB() {
        if (!$this->dbcon || !$this->dbconUser || !$this->dbconGroup) {
            $this->dbconUser  = $this->_createConnection('User');
            $ret = ($this->dbconUser !== FALSE);
            $this->dbconGroup = $this->_createConnection('Group');
            $ret = $ret && ($this->dbconGroup !== FALSE);
            $this->dbcon = $this->dbconUser;
        }else {
            $ret = true; //connections already open
        }
        if(!$ret){
            $this->_debug("MySQL err: DB can't be opened.", -1, __LINE__, __FILE__);
        }
        return $ret;
    }

    private function _createConnection( $server ) {
        $con = @mysqli_connect($this->getConf("server$server"), $this->getConf('user'), $this->getConf('password'), $this->getConf("database$server"));
        if ($con) {
            if ((mysqli_select_db($con, $this->getConf("database$server")))) {
                if ((preg_match('/^(\d+)\.(\d+)\.(\d+).*/', mysqli_get_server_info($con), $result)) == 1) {
                    $this->dbver = $result[1];
                    $this->dbrev = $result[2];
                    $this->dbsub = $result[3];
                }
                if ($this->getConf('charset')) {
                    mysqli_query($con, 'SET CHARACTER SET "'.$this->getConf('charset').'"');
                }
                return $con; // connection and database successfully opened
            } else {
                mysqli_close($con);
                $this->_debug("MySQL err: ".mysqli_connect_errno().". No access to server database {$this->getConf("server$server")}:{$this->getConf("database$server")}.", -1, __LINE__, __FILE__);
            }
        } else {
            $this->_debug("MySQL err: ".mysqli_connect_errno().". Connection to {$this->getConf('user')}@{$this->getConf("server$server")} not possible.", -1, __LINE__, __FILE__);
        }
        return false; // connection failed
    }

    /**
     * Closes a database connection.
     * @culpable Rafael Claver
     */
    protected function _closeDB() {
        if($this->dbconUser) {
            mysqli_close($this->dbconUser);
            $this->dbconUser = 0;
        }
        if($this->dbconGroup) {
            mysqli_close($this->dbconGroup);
            $this->dbconGroup = 0;
        }
        $this->dbcon = 0;
    }

    /**
     * Sends a SQL query to the database and transforms the result into
     * an associative array.
     * This function is only able to handle queries that returns a
     * table such as SELECT.
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     * Selecciona la conexión en función de la tabla implicada
     * @culpable Rafael Claver
     * @param string $query  SQL string that contains the query
     * @return array with the result table
     */
    protected function _queryDB($query) {
        if ($this->getConf('debug') >= 2) {
            $this->_debug('MySQL query: '.hsc($query), 0, __LINE__, __FILE__);
        }

        $resultarray = array();
        $this->dbcon = (preg_match("/wiki_(|user_)group/", $query) === 1) ? $this->dbconGroup : $this->dbconUser;
        if ($this->dbcon) {
            $result = ($query) ? mysqli_query($this->dbcon, $query) : false;
            if ($result) {
                while($t = mysqli_fetch_assoc($result)){
                    $resultarray[] = $t;
                }
                mysqli_free_result($result);
                return $resultarray;
            }
            $this->_debug('MySQL err: '.mysqli_error($this->dbcon), -1, __LINE__, __FILE__);
        }
        return false;
    }

    /**
     * Sends a SQL query to the database
     *
     * This function is only able to handle queries that returns
     * either nothing or an id value such as INPUT, DELETE, UPDATE, etc.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param string $query  SQL string that contains the query
     * @return int|bool insert id or 0, false on error
     */
    protected function _modifyDB($query, $typeResult="numeric") {
        $this->_debug('MySQL query: '.hsc($query), 0, __LINE__, __FILE__, 2);

        $this->dbcon = (preg_match("/wiki_(|user_)group/", $query) === 1) ? $this->dbconGroup : $this->dbconUser;
        if ($this->dbcon) {
            $result = @mysqli_query($this->dbcon, $query);
            if ($result) {
                $rc = mysqli_insert_id($this->dbcon); //give back ID on insert
                if ($rc !== false)
                    return ($typeResult == "numeric") ? $rc : $result;
            }
            $this->_debug('MySQL err: '.mysqli_error($this->dbcon), -1, __LINE__, __FILE__);
        }
        return FALSE;
    }

    /**
     * Locked a list of tables for exclusive access so that modifications
     * to the database can't be disturbed by other threads. The list
     * could be set with $conf['plugin']['authmoodle']['TablesToLock'] = array()
     *
     * If aliases for tables are used in SQL statements, also this aliases
     * must be locked. For eg. you use a table 'user' and the alias 'u' in
     * some sql queries, the array must looks like this (order is important):
     *   array("user", "user AS u");
     *
     * MySQL V3 is not able to handle transactions with COMMIT/ROLLBACK
     * so that this functionality is simulated by this function. Nevertheless
     * it is not as powerful as transactions, it is a good compromise in safty.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param string $mode  could be 'READ' or 'WRITE'
     * @return bool
     */
    protected function _lockTables($mode) {
        if($this->dbcon) {
            $ttl = $this->getConf('TablesToLock');
            if(is_array($ttl) && !empty($ttl)) {
                if($mode == "READ" || $mode == "WRITE") {
                    $sql = "LOCK TABLES ";
                    $cnt = 0;
                    foreach($ttl as $table) {
                        if($cnt++ != 0) $sql .= ", ";
                        $sql .= "$table $mode";
                    }
                    $this->_modifyDB($sql);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Unlock locked tables. All existing locks of this thread will be
     * abrogated.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    protected function _unlockTables() {
        if($this->dbcon) {
            $this->_modifyDB("UNLOCK TABLES");
            return true;
        }
        return false;
    }

    protected function retrieveUsersFromGroup($group){
        $result = "";

        if (!is_array($group)) {
            $tmp = str_replace("'", "", $group);
            $group = $tmp = explode(",", $tmp);
        }
        if (!empty($group) && is_array($group)){
            $tmp = "";
            foreach ($group as $g) {
                $tmp .= "'".$this->_escape(trim($g, "'"))."',";
            }
            $tmp = substr($tmp, 0, -1);
        }

        if ($this->_openDB()) {
            $this->dbcon = $this->dbconGroup;
            $this->_lockTables("READ");
            $sql = str_replace('%{groups}', $tmp, $this->getConf('getUsersFromGroups'));
            $sqlresult = $this->_queryDB($sql);

            $this->_unlockTables();

            foreach($sqlresult as $row) {
                $result .= $row['user_id'].",";
            }
            $result = substr($result, 0, -1);
        }
        return $result;

    }

    /**
     * Transforms the filter settings in an filter string for a SQL database
     * The database connection must already be established, otherwise the
     * original SQL string without filter criteria will be returned.
     *
     * @author Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     *
     * @param  string $sql     SQL string to which the $filter criteria should be added
     * @param  array $filter  array of filter criteria as pairs of item and pattern
     * @return string SQL string with attached $filter criteria on success, original SQL string on error
     */
    protected function _createSQLFilter($sql, $filter) {
        $SQLfilter = "";
        $cnt       = 0;

        if($this->dbcon) {
            foreach($filter as $item => $pattern) {
                if ($item !== 'grps' && $item !== 'moodle') {
                    $tmp = '%'.$this->_escape($pattern).'%';
                }
                if($item == 'user') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{user}', $tmp, $this->getConf('FilterLogin'));
                } else if($item == 'name') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{name}', $tmp, $this->getConf('FilterName'));
                } else if($item == 'mail') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{email}', $tmp, $this->getConf('FilterEmail'));
                } else if($item == 'moodle') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{moodle}', $pattern, $this->getConf('FilterMoodle'));
                } else if($item == 'editor') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{editor}', $pattern, $this->getConf('FilterEditor'));
                //En esta consulta NO se puede preguntar directamente por los grupos dado que
                //se accede a ellos a través una conexión distinta. En consecuencia, se obtienen
                //primero los ID de usuarios a partir de los grupos y con estos se filtra la base de datos
                } else if($item == 'grps') {
                    $tmp = $this->retrieveUsersFromGroup($pattern);
                    if ($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{values}', $tmp, $this->getConf('FilterByUserId'));
                } else if($item == 'username_name') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{name}', $tmp, $this->getConf('FilterUsernameName'));
                } else if($item == 'usernames') {
                    if($cnt++ > 0) $SQLfilter .= " AND ";
                    $SQLfilter .= str_replace('%{values}', $tmp, $this->getConf('FilterByUsernames'));
                }
            }

            if(strlen($SQLfilter)) {
                $glue = strpos(strtolower($sql), "where") ? " AND " : " WHERE ";
                $sql  = $sql.$glue.$SQLfilter;
            }
        }

        return $sql;
    }

    /**
     * Escape a string for insertion into the database
     *
     * @author Andreas Gohr <andi@splitbrain.org>
     *
     * @param  string  $string The string to escape
     * @param  boolean $like   Escape wildcard chars as well?
     * @return string
     */
    protected function _escape($string, $lower=FALSE, $like=FALSE) {
        if($this->dbcon) {
            $string = mysqli_real_escape_string($this->dbcon, $string);
        } else {
            $string = addslashes($string);
        }
        if ($lower) {
            $string = strtolower($string);
        }
        if ($like) {
            $string = addcslashes($string, '%_');
        }
        return $string;
    }

    public function cleanUser($user) {
        return trim($user);
    }

    /**
     * Wrapper around msg() but outputs only when debug is enabled
     *
     * @param string $message
     * @param int    $err
     * @param int    $line
     * @param string $file
     * @return void
     */
    protected function _debug($message, $err, $line, $file, $level=1) {
        if ($this->getConf('debug') < $level) return;
        msg($message, $err, $line, $file);
        $tag = $err===0?"Info: ":"Error($err): ";
        $date = date("d-m-Y H:i:s");
        $f = $this->getConf('logFile');
        if($f[0]!=='/'){
            $f = DOKU_INC."lib/plugins/tmp/$f";
        }
        file_put_contents($f, "$date ($tag)=> $message ($file:$line)\n", FILE_APPEND);
    }
}
