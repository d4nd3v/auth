<?php

namespace D4nd3v\Auth;

use Illuminate\Console\Command;
use League\Flysystem\Directory;

class AuthCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'generate:auth  {--overwrite=false}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate Complete Laravel Auth';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */


    private $overwriteExistingFiles = false;
    private $templatePath = (__DIR__ . '/templates/');



    public function handle()
    {
        if($this->option('overwrite')=="true") {
            $this->overwriteExistingFiles =  true;
        }
        $this->createController();
        $this->createViews();
        $this->createNotifications();
        $this->createMigrations();
        $this->createModels();
        $this->createLang();


        $this->info("Done.");

    }





    public function createController()
    {
        $destionationFolder = app_path('Http/Controllers');
        $this->createFileFromTemplate($this->templatePath . 'controllers/AuthController.php'
            , $destionationFolder . '/AuthController.php');
    }



    private function createFileFromTemplate($source, $destination)
    {
        if(!\File::exists($destination) || $this->overwriteExistingFiles) {
            \File::put($destination, \File::get($source));
        } else {
            $this->warn('File: ' . $destination. ' already exist.');
        }
    }



    public function createViews()
    {
        $destionationFolder = resource_path('views/auth');
        if(!\File::exists($destionationFolder)) {
            \File::makeDirectory($destionationFolder, 0755, true);
        }
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'login.blade.php.txt', $destionationFolder . '/login.blade.php');
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'register.blade.php.txt', $destionationFolder . '/register.blade.php');
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'activate.blade.php.txt', $destionationFolder . '/activate.blade.php');
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'reactivate.blade.php.txt', $destionationFolder . '/reactivate.blade.php');
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'activated.blade.php.txt', $destionationFolder . '/activated.blade.php');
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'email.blade.php.txt', $destionationFolder . '/email.blade.php');
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'reset.blade.php.txt', $destionationFolder . '/reset.blade.php');
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'changed.blade.php.txt', $destionationFolder . '/changed.blade.php');
        $this->createFileFromTemplate($this->templatePath . 'views/' . 'change.blade.php.txt', $destionationFolder . '/change.blade.php');

    }


    private function createNotifications()
    {
        $destionationFolder = app_path('Notifications');
        if(!\File::exists($destionationFolder)) {
            \File::makeDirectory($destionationFolder, 0755, true);
        }
        $this->createFileFromTemplate($this->templatePath . 'notifications/' . 'ActivateAccount.php.txt', $destionationFolder . '/ActivateAccount.php');
        $this->createFileFromTemplate($this->templatePath . 'notifications/' . 'PasswordReset.php.txt', $destionationFolder . '/PasswordReset.php');

    }

    private function createMigrations()
    {
        $destionationFolder = database_path('migrations/auth/');
        if(!\File::exists($destionationFolder)) {
            \File::makeDirectory($destionationFolder, 0755, true);
        }
        $this->createFileFromTemplate($this->templatePath . 'migrations/' . '2017_01_23_100000_create_activations_table.php.txt'
            , $destionationFolder . '/2017_01_23_100000_create_activations_table.php');
        $this->createFileFromTemplate($this->templatePath . 'migrations/' . '2017_01_23_000000_create_users_table.php.txt'
            , $destionationFolder . '/2017_01_23_000000_create_users_table.php');
        $this->createFileFromTemplate($this->templatePath . 'migrations/' . '2017_01_23_100000_create_password_resets_table.php.txt'
            , $destionationFolder . '/2017_01_23_100000_create_password_resets_table.php');
    }




    private function createModels()
    {
        $destionationFolder = app_path('Models');
        if(!\File::exists($destionationFolder)) {
            \File::makeDirectory($destionationFolder, 0755, true);
        }
        $this->createFileFromTemplate($this->templatePath . 'models/' . 'Activation.php.txt', $destionationFolder . '/Activation.php');
        $this->createFileFromTemplate($this->templatePath . 'models/' . 'User.php.txt', $destionationFolder . '/User.php');
    }



    private function createLang()
    {
        $destionationFolder = resource_path('lang/en');
        if(!\File::exists($destionationFolder)) {
            \File::makeDirectory($destionationFolder, 0755, true);
        }
        $this->createFileFromTemplate($this->templatePath . 'lang/' . 'auth-d4nd3v.php.txt', $destionationFolder . '/auth-d4nd3v.php');
    }


}
