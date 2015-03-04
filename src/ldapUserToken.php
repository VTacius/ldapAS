<?php
/**
 * @name ldapUserToken
 * @author vtacius
 */
namespace LdapAS;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use \Symfony\Component\Security\Core\Role\RoleInterface;

class ldapUserToken extends AbstractToken {
    private $user;
    private $credentials;
    private $roles = array();
    
    function getUser() {
        return $this->user;
    }

    function getRoles() {
        return $this->roles;
    }

    function setUser($user) {
        $this->user = $user;
    }

    function setRoles($roles) {
        $this->roles = $roles;
    }

    public function __construct($usuario, $credenciales, array $roles = array()) {
        parent::__construct($roles);
        // If the user has roles, consider it authenticated
        $this->setAuthenticated(count($roles) > 0);
        $this->credentials = $credenciales;
        $this->user = $usuario;
    }

    public function getCredentials() {
        return $this->credentials;
    }
}
