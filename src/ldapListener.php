<?php
/**
 * @name ldapListener
 * @author vtacius
 */
namespace LdapAS;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

// TODO: En algún momento de nuestras vidas, debe usarse nuestro propio token,
// supongo que esto tambien podría ayudar a solucionar el problema que se explica en ldapAuthProvider
// sobre no poder configuarar ldapUser como $user
// use Agenlad\Controller\ldapLogin\UsernamePasswordToken;

class ldapListener implements ListenerInterface{
    
    protected $securityContext;
    protected $authenticationManager;
    private $app;
    
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, \Silex\Application $app) {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->app = $app;
    }
    
    public function handle(GetResponseEvent $event) {
        $credenciales = $event->getRequest();
        $usuario = $credenciales->get('_username');
        $password = $credenciales->get('_password');

        // TODO: Heredado por compatibilidad con el ejemplo padre, o al menos eso creo
        if (empty($usuario) || empty($password)) {
            return;
        }
      
        // TODO: He supuesto que esta especie de pre-token no sobrevive por mucho, ya que no se ve con rol 'administrador'
        // que por cierto es un rol inválido, en el resto del flujo
        $token = new UsernamePasswordToken($usuario, $password, array('admininistrador'));
        $token->setUser($usuario);
        
        try {
            // Autentico el token
            $authToken = $this->authenticationManager->authenticate($token);
            // Configuro el token
            $this->securityContext->setToken($authToken);
            // Llegado a este punto, todo ha terminado
            return;
        } catch (AuthenticationException $failed) {
            // To deny the authentication clear the token. This will redirect to the login page.
            // Make sure to only clear your token, not those of other authentication listeners.
             $token = $this->securityContext->getToken();
             if ($token instanceof UsernamePasswordToken && $this->providerKey === $token->getProviderKey()) {
                 $this->securityContext->setToken(null);
             }
             return;
        }

        // By default deny authorization
        $response = new Response();
        $response->setStatusCode(Response::HTTP_FORBIDDEN);
        $event->setResponse($response);
    }

}
