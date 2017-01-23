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
        $this->info("Done.");

    }





    public function createController()
    {
        $controllerPath = app_path('Http/Controllers').'/AuthController.php';
        if(\File::exists($controllerPath) && !$this->overwriteExistingFiles) {
            $this->warn('Controller '.$controllerPath.' already exists, it is not overwritten.');
        } else {
            $controllerTemplate = \File::get(($this->templatePath . 'AuthController.php'));
            $bytesWritten = \File::put($controllerPath, $controllerTemplate);
            if ($bytesWritten === false)
            {
                $this->error('Error writing to file'.$controllerPath);
            }
        }
    }


    public function createViews()
    {
        $viewsPath = resource_path('views') .'/auth';
        if(!\File::exists($viewsPath)) {
            \File::makeDirectory($viewsPath, 0755, true);
        }
        $this->createViewFileFromTemplate('login_blade.txt', 'login.blade.php');
        $this->createViewFileFromTemplate('register_blade.txt', 'register.blade.php');
        $this->createViewFileFromTemplate('activate_blade.txt', 'activate.blade.php');
    }


    private function createViewFileFromTemplate($source, $destination)
    {
        $createViewTemplate = \File::get(($this->templatePath . 'views/'.$source));
        $viewCreatePath = resource_path('views') .'/auth/'.$destination;
        if(!\File::exists($viewCreatePath) || $this->overwriteExistingFiles) {
            \File::put($viewCreatePath, $createViewTemplate);
        }
    }










}
