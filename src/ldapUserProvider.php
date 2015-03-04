<?php
/**
 * @name ldapUserProvider
 * @author vtacius
 */
namespace LdapAS;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Doctrine\DBAL\Connection;

use LdapAS\ldapUser;
use LdapPM\Modelos\modeloShadowAccount;


/**
 * Soy sincero con respecto al hecho que no entiendo del todo el flujo de todo este proceso
 * sin embargo, al momemto de escribir esto, incluso los roles funcionan
 */
class ldapUserProvider implements UserProviderInterface {
    
    private $db;
    private $app;

    public function __construct(Connection $db, \Silex\Application $app) {
        $this->app = $app;
        $this->db = $db;
    }

    public function loadUserByUsername($username) {
        $ldap = new modeloShadowAccount($this->app['LdapAS.fichero']);
        $ldap->conectar('default', 'admin');
        $ldap->setUid($username);
        if (!$ldap->verificaExistencia()) {
            throw new UsernameNotFoundException(sprintf('El usuario %s no existe', $username));
        }        
        $attr = $this->obtenerRol($username);
        $roles = $attr['rol'];
        $dnUser = $ldap->getDnObjeto();
        $dominio = $this->obtenerDominio($dnUser, $attr['dominio']);
        $credenciales = "Falsedad, no necesito en realidad este parametro";
        return new ldapUser($username, $credenciales, explode(',', $roles), $dominio, $dnUser);
    }
    
    public function refreshUser(UserInterface $user) {
    // TODO: Tampoco esta función tiene mucho sentido a estas alturas de la vida
        $class = get_class($user);
        if (!$this->supportsClass($class)) {
            throw new UnsupportedUserException(sprintf('Instancias de clase "%s" no son soportadas.', get_class($user)));
        }
        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class) {
        // TODO: A estas alturas del partido, siguen sin entender del todo que pinta este dentro del proceso, ya que de todos modos
        // resultaba en falso al punto de escribir esto
        return $class === 'LdapAS\ldapUser';
    }
    
    /**
     * Obtiene el dominio tomando en base al DN del usuario
     * Saco esta función de Utilidades para mejorar la independencia de todo el módulo.
     * @param string $dn
     * @return string
     */
    private function convertidorDominio($dn){
        $pattern = "(dc=(?P<componentes>[A-Za-z]+))";
        $matches = array();
        $dominio = "";
        preg_match_all($pattern, $dn, $matches );
        foreach ($matches['componentes'] as $componentes){
                $dominio .= $componentes . ".";
        }
        return rtrim($dominio, ".");
    }
    
    /**
     * Si $dominio esta vacío, obtiene el dominio DNS del usuario en base 
     * al DN
     * @param string $dnUsuario
     * @param string $dominio
     * @return string
     */
    private function obtenerDominio($dnUsuario, $dominio){
        if (empty($dominio)) {
            return $this->convertidorDominio($dnUsuario);
        }
        return $dominio;
    }
    
    /**
     * Obtiene el rol del usuario en la base de datos para administradores 
     * o asigna uno por defecto para usuario vil y silvestre
     * @param string $usuario
     * @return array
     */
    private function obtenerRol($usuario){
        $sentencia = "select rol, dominio from usuario where user=:arguser";
        $params = array('arguser'=>$usuario);
        $query = $this->db->executeQuery($sentencia, $params);
        if (($user = $query->fetch())) {
            return $user;
        } else {
            //Se asigna un rol por defecto
            return array('rol'=>'ROL_USER', 'dominio'=>'');
        }
    }
}
