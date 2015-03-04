<?php
/**
 * @name ldapUser
 * @author vtacius
 */
namespace LdapAS;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\EquatableInterface;

class ldapUser implements UserInterface, EquatableInterface {
    private $username;
    private $password;
    private $salt;
    private $roles;
    private $dnUser;
    private $dominio;
    
    public function __construct($username, $password, array $roles, $dominio, $dnUser) {
        $this->username = $username;
        $this->password = $password;
        $this->roles = $roles;
        $this->dominio = $dominio;
        $this->dnUser = $dnUser;
    }

    function getDominio() {
        return $this->dominio;
    }

    function getDnUser() {
        return $this->dnUser;
    }

    function setDnUser($dnUser) {
        $this->dnUser = $dnUser;
    }
        
    public function getRoles() {
        return $this->roles;
    }
    
    public function getPassword() {
        return $this->password;
    }
    
    public function getSalt() {
        return $this->salt;
    }
    
    public function getUsername() {
        return $this->username;
    }
    
    public function eraseCredentials() {
    }
    
    public function isEqualTo(UserInterface $user) {
        if (!$user instanceof ldapLogin\ldapUser) {
            return false;
        }
        if ($this->password !== $user->getPassword()) {
            return false;
        }
        if ($this->salt !== $user->getSalt()) {
            return false;
        }
        if ($this->username !== $user->getUsername()) {
            return false;
        }
        return true;
    }
    
    public function __toString() {
        return $this->username;
    }
}
