<?php

namespace D4nd3v\Auth;

use Illuminate\Console\Command;
use League\Flysystem\Directory;

class CRUDCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'generate:auth';

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

        $this->info("Done.");

    }





}
