<?php
/**
 * @name ldapAuthProvider
 * @author vtacius
 */
namespace LdapAS;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

// No sé si recompensarte con una galleta o mandarte a la chingada por joder 
// tanto tiempo con algo tan sencillo
//use Agenlad\Controller\ldapLogin\UsernamePasswordToken;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class ldapAuthProvider implements AuthenticationProviderInterface{
    private $userProvider;

    private $mono;
    public function __construct(UserProviderInterface $userProvider, \Silex\Application $app) {
        $this->mono = $app['monolog'];
#        $this->mono->addInfo('Estoy en ldapAuthProvider');
        $this->userProvider = $userProvider;
    }

    /**
     * Especifica cuales son cuales tipos de token están permitidos
     * @param TokenInterface $token
     * @return type
     */
    public function supports(TokenInterface $token) {
#        $this->mono->addInfo('¿Lo soporta?');
        return $token instanceof UsernamePasswordToken;
    }

    /**
     * Todo parece indicar que es en este lugar donde la magia pasa
     * @param TokenInterface $token
     * @return \Agenlad\Controller\ldapLogin\WsseUserToken
     * @throws AuthenticationException
     */
    public function authenticate(TokenInterface $token) {
        // TODO: La carga de este usuario debe suceder donde nuestro proveedor de usuarios, cosa que pasa por el momento
        // pero que tiene mucho trabajo por afinar
        $user = $this->userProvider->loadUserByUsername($token->getUsername());
        $credenciales = $token->getCredentials();
        if ($this->logueo($token->getUsername(), $credenciales)) {
            $this->mono->addInfo('# La autenticacion es un éxito. Creamos un token autenticado');
            $authenticatedToken = new UsernamePasswordToken($user->getUsername(), $user->getPassword(), 'LDAP', $user->getRoles());
	    $this->mono->addInfo('# Estoy por setear el usuario');
            $authenticatedToken->setUser($user->getUsername());
            $authenticatedToken->setAttribute('dn',$user->getDnUser());
            $authenticatedToken->setAttribute('credencial', $credenciales);
            $authenticatedToken->setAttribute('dominio', $user->getDominio());
            return $authenticatedToken;
        } else {
            throw new AuthenticationException('La autenticacion contra LDAP ha fallado');
        }
    }
    
    /**
     * He aquí como sucede la magia, de la forma en que el avance de nuestra librería nos deja
     * @param type $usuario
     * @param type $password
     * @return type
     */
    private function logueo($usuario, $password){
        $ldap = new \LdapPM\Modelos\modeloShadowAccount('default', 'lector');
        $ldap->setUid($usuario);
        $dnUsuario = $ldap->getDnObjeto();
        //TODO: Del DN, serà necesario obtener el dominio del usuario
        $autenticacion = new \LdapPM\Modelos\modeloShadowAccount('default', $dnUsuario, $password);
        return $autenticacion->estaAutenticado();       
    }
}
