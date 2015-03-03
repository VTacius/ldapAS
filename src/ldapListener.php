<?php
/**
 * @name ldapListener
 * @author vtacius
 */
namespace LdapAS;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

//use Agenlad\Controller\ldapLogin\UsernamePasswordToken;

class ldapListener implements ListenerInterface{
    
    protected $securityContext;
    protected $authenticationManager;
    private $app;
    
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, \Silex\Application $app) {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->app = $app;
#        $this->app['monolog']->addInfo("Estoy en ldapListener personalizado");
    }
    
    public function handle(GetResponseEvent $event) {
        $credenciales = $event->getRequest();
        $usuario = $credenciales->get('_username');
        $password = $credenciales->get('_password');

        // TODO: ¿De que putas se supone que va esto?
        if (empty($usuario) || empty($password)) {
            return;
        }
      
        $token = new UsernamePasswordToken($usuario, $password, array('admininistrador'));
        $token->setUser($usuario);
        
        try {
            $this->app['monolog']->addInfo("Autentico el token");
            $authToken = $this->authenticationManager->authenticate($token);
            $this->app['monolog']->addInfo("Configuro el token");
            $this->securityContext->setToken($authToken);
            $this->app['monolog']->addInfo('Si veo, esto, todo esta terminado');
            return;
        } catch (AuthenticationException $failed) {
            $fallo = $failed->getMessage();
#            $this->app['monolog']->addInfo("Estoy en catch de handle de ldapListener personalizado $fallo");
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
