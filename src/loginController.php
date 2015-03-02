<?php
/**
* @name loginController
* @author vtacius
*/
namespace ldapLogin;
use Silex\Application;
use Silex\ControllerProviderInterface;
use Symfony\Component\HttpFoundation\Request;
class loginController implements ControllerProviderInterface{
    public function mostrarLogin(Request $request, Application $app){
        print "Este mensaje desde un metodo distinto";
    }
    public function connect(Application $app) {
        $controllers = $app['controllers_factory'];
        $controllers->get('/', function (Request $request, Application $app) {
            $error = $app['security.last_error']($request);
            $user = $app['session']->get('_security.last_username');
            $datos = array('error' => $error, 'user' => $user);
            return $app['twig']->render('Login/login.html.twig', $datos);
        });
        $controllers->post('/auth', function (Request $request, Application $app) {
            $parametros = $request->request->all();
            print_r($parametros);
            return 'Aca nos logueamos';
        });
        return $controllers;
    }
}
