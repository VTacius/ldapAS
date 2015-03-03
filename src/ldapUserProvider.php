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
 * Tenemos algo sin sentido que sin embargo funciona en determinados casos. Al menos, esto nos ayuda 
 * en cuanto a lo que tenemos que hacer
 */
class ldapUserProvider implements UserProviderInterface {
    
    private $db;
    private $app;

    public function __construct(Connection $db, \Silex\Application $app) {
        $this->app = $app;
        $this->db = $db;
	$class = get_class($this);
        $this->app['monolog']->addInfo("Esto en ldapUserProvider personalizado $class");
    }

    public function loadUserByUsername($username) {
        $ldap = new modeloShadowAccount('default', 'admin');
        $ldap->setUid($username);
        if (!$ldap->verificaExistencia()) {
            throw new UsernameNotFoundException(sprintf('El usuario %s no existe', $username));
        }        
        $atributos = $this->obtenerRol($username);
        $rol = $atributos['rol'];
        $dnUser =  $ldap->getDnObjeto();
        $dominio =$this->obtenerDominio($dnUser, $atributos['dominio']);
        $credenciales = "Falsedad, no necesito en realidad este parametro";
        return new ldapUser($username, $credenciales, explode(',', $rol), $dominio, $dnUser);
    }

    public function refreshUser(UserInterface $user) {
        $this->app['monolog']->addInfo("Esto en refreshUser de ldapUserProvider personalizado");
        if (!$user instanceof ldapLogin\ldapUserProvider) {
            $this->app['monolog']->addInfo("Suponenemos que este es el problema");
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }
        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class) {
        $this->app['monolog']->addInfo("Esto en supportsClass de ldapUserProvider personalizado $class");
        return $class === 'ldapLogin\ldapUser';
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
#            $this->app['monolog']->addInfo('Este rol le asignaremos al usuario '. $user['rol']);
            return $user;
        } else {
            //Se asigna un rol por defecto
#            $this->app['monolog']->addInfo("Algo ha fallado con obtenerRol. Obtenemos valores por defecto");
            return array('rol'=>'ROL_USER', 'dominio'=>'');
        }
    }
}
