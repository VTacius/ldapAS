<?php
/**
 * @name ldapAuthProvider
 * @author vtacius
 */

namespace LdapAS;

use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;

// TODO: En algún momento de nuestras vidas, debe usarse nuestro propio token,
// supongo que esto tambien podría ayudar a solucionar el problema que se explica en el authenticate 
// sobre no poder configuarar ldapUser como $user
// use Agenlad\Controller\ldapLogin\UsernamePasswordToken;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class ldapAuthProvider implements AuthenticationProviderInterface{
    
    private $userProvider;
    private $app;
    
    public function __construct(UserProviderInterface $userProvider, \Silex\Application $app) {
        $this->app = $app;
        $this->userProvider = $userProvider;
    }

    /**
     * Especifica cuales son cuales tipos de token están permitidos
     * @param TokenInterface $token
     * @return type
     */
    public function supports(TokenInterface $token) {
        return $token instanceof UsernamePasswordToken;
    }

    /**
     * Todo parece indicar que es en este lugar donde la magia pasa
     * @param TokenInterface $token
     * @return \Agenlad\Controller\ldapLogin\UsernamePasswordToken
     * @throws AuthenticationException
     */
    public function authenticate(TokenInterface $token) {
        // TODO: La carga de este usuario debe suceder donde nuestro proveedor de usuarios, cosa que pasa por el momento
        // pero que tiene mucho trabajo por afinar
        $user = $this->userProvider->loadUserByUsername($token->getUsername());
        $credenciales = $token->getCredentials();
        if ($this->logueo($token->getUsername(), $credenciales)) {
            # La autenticacion es un éxito. Creamos un token autenticado
            $authenticatedToken = new UsernamePasswordToken($user->getUsername(), $user->getPassword(), 'LdapAS', $user->getRoles());
            // A continuación, llenamos el token con información sobre el usuario:
            // Resulta que en lugar de $user->getUsername debería ser $user, para mandar todo el objeto a 
            // guardarse en el token, 
            // TODO: Por el momento no encuentro la manera de registrar la
            // clase ldapUser como un ¿Proveedor valido?
            $authenticatedToken->setUser($user);
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
        $ldap = new \LdapPM\Modelos\modeloShadowAccount($this->app['LdapAS.fichero']);
        $ldap->conectar('default', 'lector');
        $ldap->setUid($usuario);
        $dnUsuario = $ldap->getDnObjeto();
        //TODO: Del DN, serà necesario obtener el dominio del usuario
        $autenticacion = new \LdapPM\Modelos\modeloShadowAccount($this->app['LdapAS.fichero']);
        $autenticacion->conectar('default', $dnUsuario, $password);
        return $autenticacion->estaAutenticado();       
    }
}
